"""Verify the packet oracle itself without opening a real network socket."""
import ast
import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import unittest
from unittest.mock import patch


FIXTURE = Path(__file__).with_name('storage_replica_vm.py')


def embedded_program(name):
    tree = ast.parse(FIXTURE.read_text())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    assignment = next(n for n in function.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'program' for t in n.targets))
    assert isinstance(assignment.value, ast.Call)
    return assignment.value.func.value.value


def checksum(data):
    if len(data) % 2:
        data += bytes(1)
    total = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


class GuardPacketOracleTests(unittest.TestCase):
    def test_underlay_probe_is_valid_payload_free_ipv4_tcp_and_closes_socket(self):
        sent = []

        class RawSocket:
            closed = False

            def bind(self, address):
                self.address = address

            def send(self, frame):
                sent.append(frame)
                return len(frame)

            def close(self):
                self.closed = True

        sock = RawSocket()
        parameters = ('lab0', '10.37.129.212', '10.246.75.1', '02:00:73:00:00:01', 27791)
        code = embedded_program('raw_inbound').replace('PARAMETERS', repr(parameters))
        output = io.StringIO()
        with patch('socket.socket', return_value=sock) as create, \
             patch.object(socket, 'AF_PACKET', 17, create=True), \
             patch('builtins.open', return_value=io.StringIO('02:00:73:00:00:02\n')), \
             patch('time.sleep'), contextlib.redirect_stdout(output):
            exec(compile(code, str(FIXTURE), 'exec'), {})
        create.assert_called_once_with(17, socket.SOCK_RAW)
        self.assertTrue(sock.closed)
        self.assertEqual(sock.address, ('lab0', 0))
        self.assertEqual(json.loads(output.getvalue())['payload_bytes'], 0)
        self.assertEqual(len(sent), 3)
        for frame in sent:
            self.assertEqual(len(frame), 54)
            self.assertEqual(frame[12:14], bytes.fromhex('0800'))
            ip, tcp = frame[14:34], frame[34:]
            self.assertEqual(ip[0], 0x45)
            self.assertEqual(int.from_bytes(ip[2:4], 'big'), 40)
            self.assertEqual(ip[9], socket.IPPROTO_TCP)
            self.assertEqual(socket.inet_ntoa(ip[12:16]), parameters[1])
            self.assertEqual(socket.inet_ntoa(ip[16:20]), parameters[2])
            self.assertEqual(checksum(ip), 0)
            self.assertEqual(checksum(ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp)) + tcp), 0)
            self.assertEqual(struct.unpack('!HH', tcp[:4]), (40017, 27791))
            self.assertEqual(tcp[12:14], bytes([0x50, 0x02]))

    def test_egress_oracle_program_compiles_for_present_and_absent_interface(self):
        for present in (True, False):
            source = embedded_program('route_probe').replace('PARAMETERS', repr(
                ('lab0', '10.246.75.2', 27791, '10.246.75.1', present)))
            compile(source, str(FIXTURE), 'exec')

    def test_fixture_counter_normalization_never_hides_policy_or_handle_changes(self):
        tree = ast.parse(FIXTURE.read_text())
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'stable_nft')
        namespace = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(FIXTURE), 'exec'), namespace)
        normalize = namespace['stable_nft']
        original = {'rule': {'handle': 5, 'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}}
        counters = json.loads(json.dumps(original))
        counters['rule']['expr'][0]['counter'] = dict(packets=9, bytes=500)
        self.assertEqual(normalize(original), normalize(counters))
        changed = json.loads(json.dumps(counters))
        changed['rule']['expr'][-1] = {'accept': None}
        self.assertNotEqual(normalize(original), normalize(changed))
        changed = json.loads(json.dumps(original))
        changed['rule']['handle'] = 6
        self.assertNotEqual(normalize(original), normalize(changed))


if __name__ == '__main__':
    unittest.main()
