#!/usr/bin/env python3
"""Finite loopback ingress qualification; only directly owned children are stopped.

Uses the explicit ignored ingress-only test entry, not `royak watch`. No Docker,
control-plane API, live state, public listeners or shared cleanup commands.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time


def atomic(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


async def backend(root, index):
    db = sqlite3.connect(root / 'effects.sqlite')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')

    async def handle(reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            lines = header.decode('latin1').split('\r\n')
            method, path, _ = lines[0].split()
            headers = {k.lower(): v.strip() for k, v in (line.split(':', 1) for line in lines[1:] if ':' in line)}
            body = await reader.readexactly(int(headers.get('content-length', '0')))
            identity = int(headers['x-probe-id'])
            digest = hashlib.sha256(body).hexdigest()
            if method not in ('GET', 'HEAD'):
                db.execute('INSERT INTO effects VALUES(?,?,?,?)', (identity, index, method, digest))
                db.commit()  # Durable application effect precedes any acknowledgement.
            mode_path = root / f'backend-{index}.mode.json'
            mode = json.loads(mode_path.read_text()) if mode_path.exists() else {}
            while mode.get('hold') == identity:
                await asyncio.sleep(.02)
                mode = json.loads(mode_path.read_text())
            if mode.get('drop'):
                writer.transport.abort()
                return
            response = json.dumps({'id': identity, 'backend': index, 'method': method, 'path': path,
                'host': headers.get('host'), 'cookie': headers.get('cookie'), 'body_sha256': digest}).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                + str(len(response)).encode() + b'\r\nConnection: close\r\n\r\n' + response)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    atomic(root / f'backend-{index}.ready.json', {'port': server.sockets[0].getsockname()[1], 'pid': os.getpid()})
    async with server:
        await server.serve_forever()


class Lab:
    def __init__(self, args):
        self.args, self.root = args, args.root
        self.children, self.logs, self.ports, self.results = [], [], {}, []
        self.expected_writes = {}

    async def spawn(self, command, label, environment=None):
        log = (self.root / (label + '.log')).open('wb')
        self.logs.append(log)
        child = await asyncio.create_subprocess_exec(*map(str, command), cwd=self.root, stdout=log, stderr=log,
            env=environment or dict(os.environ))
        self.children.append(child)
        return child

    async def wait_file(self, path, child):
        for _ in range(200):
            if path.exists():
                return json.loads(path.read_text())
            assert child.returncode is None, f'Owned child exited: {path.name}'
            await asyncio.sleep(.025)
        raise TimeoutError(path.name)

    async def ingress(self, members, label):
        path = self.root / (label + '.json')
        cfg = {'listen': '127.0.0.1:0', 'duration_seconds': 180, 'routes': [{'host': 'lab.test', 'path': '/',
            'backends': [['127.0.0.1', self.ports[i]] for i in members]}]}
        atomic(path, cfg)
        environment = {**os.environ, 'ROYAK_INGRESS_LAB_CONFIG': str(path)}
        child = await self.spawn([self.args.binary, '--exact', 'api::ingress_lab::ingress_only_laboratory',
            '--ignored', '--nocapture', '--test-threads=1'], label, environment)
        ready = await self.wait_file(path.with_suffix('.ready.json'), child)
        assert ready['pid'] == child.pid and not ready['control_plane_started'] and not ready['state_writer_started']
        return child, int(ready['listen'].rsplit(':', 1)[1]), path, cfg

    async def stop(self, child):
        if child.returncode is None:
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), 4)
            except asyncio.TimeoutError:
                child.kill()
                await child.wait()

    async def request(self, port, identity, method='GET', validate=True):
        body = bytes([identity % 256]) * 1024 if method == 'POST' else b''
        path = f'/echo?request={identity}&encoded=a%2Fb'
        cookie = f'session=fixture-{identity}'
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), 3)
        try:
            writer.write((f'{method} {path} HTTP/1.1\r\nHost: lab.test\r\nX-Probe-ID: {identity}\r\n'
                f'Cookie: {cookie}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body)
            await writer.drain()
            header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 18)
            lines = header.decode('latin1').split('\r\n')
            status = int(lines[0].split()[1])
            headers = {k.lower(): v.strip() for k, v in (line.split(':', 1) for line in lines[1:] if ':' in line)}
            payload = await reader.readexactly(int(headers['content-length']))
            value = json.loads(payload) if status == 200 else None
            if validate:
                assert status == 200, (status, payload[:200])
                expected = {'id': identity, 'method': method, 'path': path, 'host': '127.0.0.1',
                            'cookie': cookie, 'body_sha256': hashlib.sha256(body).hexdigest()}
                assert all(value[k] == v for k, v in expected.items()), value
                if method == 'POST':
                    self.expected_writes[identity] = hashlib.sha256(body).hexdigest()
            return {'id': identity, 'status': status, 'backend': value['backend'] if value else None,
                    'seconds': time.monotonic() - start}
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def batch(self, port, start, count, concurrency, writes=True):
        indices = iter(range(start, start + count))
        results = []

        async def worker():
            for identity in indices:
                results.append(await self.request(port, identity, 'POST' if writes and identity % 5 == 0 else 'GET'))

        await asyncio.gather(*(worker() for _ in range(concurrency)))
        return results

    async def incomplete_request(self, port):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        try:
            writer.write(b'POST /echo?request=900002 HTTP/1.1\r\nHost: lab.test\r\nX-Probe-ID: 900002\r\n'
                         b'Content-Length: 64\r\nConnection: close\r\n\r\nshort')
            await writer.drain()
            writer.write_eof()
            response = await asyncio.wait_for(reader.read(65536), 3)
            assert not response or response.startswith(b'HTTP/1.1 400'), response[:200]
            return {'outcome': '400' if response else 'connection_closed', 'application_contact_required': False}
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def run(self):
        self.root.mkdir(parents=True, mode=0o700, exist_ok=False)
        db = sqlite3.connect(self.root / 'effects.sqlite')
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE effects(id INTEGER, backend INTEGER, method TEXT, digest TEXT)')
        db.commit()
        try:
            backends = []
            for i in range(3):
                child = await self.spawn([sys.executable, Path(__file__).resolve(), '--backend-root', self.root,
                                         '--backend-index', str(i)], f'backend-{i}')
                self.ports[i] = (await self.wait_file(self.root / f'backend-{i}.ready.json', child))['port']
                backends.append(child)
            child, port, _, _ = await self.ingress([0, 1, 2], 'healthy')
            self.results.append({'phase': 'healthy', 'requests': await self.batch(port, 0, 600, 64)})
            await self.stop(child)

            child, port, _, _ = await self.ingress([0, 1, 2], 'incomplete-request')
            invalid = await self.incomplete_request(port)
            await asyncio.sleep(.1)
            assert db.execute('SELECT COUNT(*) FROM effects WHERE id=900002').fetchone()[0] == 0
            self.results.append({'phase': 'incomplete-request', **invalid, 'application_effects': 0})
            await self.stop(child)

            atomic(self.root / 'backend-0.mode.json', {'drop': True})
            child, port, _, _ = await self.ingress([0, 1, 2], 'lost-read')
            self.results.append({'phase': 'lost-read', 'requests': await self.batch(port, 10000, 300, 64, writes=False)})
            await self.stop(child)

            child, port, _, _ = await self.ingress([0, 1], 'ambiguous-write')
            ambiguous = await self.request(port, 900000, 'POST', validate=False)
            assert ambiguous['status'] == 502
            rows = db.execute('SELECT backend FROM effects WHERE id=900000').fetchall()
            assert rows == [(0,)], rows
            self.results.append({'phase': 'ambiguous-write', 'response': ambiguous, 'effects': len(rows), 'replayed': False})
            await self.stop(child)

            atomic(self.root / 'backend-0.mode.json', {'hold': 900001})
            child, port, path, cfg = await self.ingress([0, 1], 'membership')
            held = asyncio.create_task(self.request(port, 900001, 'POST'))
            for _ in range(150):
                if db.execute('SELECT COUNT(*) FROM effects WHERE id=900001').fetchone()[0] == 1:
                    break
                await asyncio.sleep(.02)
            else:
                raise TimeoutError('Held write did not reach the application')
            cfg['routes'][0]['backends'] = [['127.0.0.1', self.ports[1]]]
            atomic(path, cfg)
            await asyncio.sleep(.3)  # More than the lab fixture's100ms publication interval.
            reads = await self.batch(port, 20000, 100, 16, writes=False)
            assert all(x['backend'] == 1 for x in reads)
            atomic(self.root / 'backend-0.mode.json', {})
            held_result = await asyncio.wait_for(held, 3)
            assert held_result['backend'] == 0
            await self.stop(backends[0])
            writes = await self.batch(port, 30000, 100, 16)
            assert all(x['backend'] == 1 for x in writes)
            self.results.append({'phase': 'membership', 'held_write': held_result,
                                 'requests': reads + writes, 'publication': 'explicit lab fixture configuration'})
            await self.stop(child)

            duplicates = db.execute('SELECT id, COUNT(*) FROM effects GROUP BY id HAVING COUNT(*) != 1').fetchall()
            assert not duplicates, duplicates
            actual = dict(db.execute('SELECT id,digest FROM effects WHERE id != 900000').fetchall())
            assert actual == self.expected_writes
            result = {'decision': 'passed', 'phases': self.results, 'acknowledged_writes': len(self.expected_writes),
                'ambiguous_write_effects': 1, 'duplicate_effects': 0, 'live_docker_access': False,
                'binary_sha256': hashlib.sha256(self.args.binary.read_bytes()).hexdigest(),
                'scope': 'loopback ingress-policy and HTTP framing; lab membership publisher, no automatic production drain claim'}
            atomic(self.root / 'acceptance.json', result)
            print(json.dumps({k: v for k, v in result.items() if k != 'phases'}), flush=True)
        finally:
            for child in reversed(self.children):
                await self.stop(child)
            for log in self.logs:
                log.close()
            db.close()
            atomic(self.root / 'cleanup.json', {'owned_children': len(self.children),
                'all_stopped': all(p.returncode is not None for p in self.children)})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--backend-root', type=Path)
    parser.add_argument('--backend-index', type=int)
    args = parser.parse_args()
    os.umask(0o077)
    if args.backend_root is not None:
        asyncio.run(backend(args.backend_root, args.backend_index))
    else:
        args.binary = args.binary.resolve()
        args.root = args.root.resolve()
        asyncio.run(Lab(args).run())
