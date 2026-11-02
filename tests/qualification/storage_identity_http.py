"""Real verified-HTTPS identity/RBAC/restart/delete regressions, no Docker or VM use."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(binary, old_binary=None, old_identity_binary=None):
    checks, launches = [], []
    with tempfile.TemporaryDirectory(prefix="rkq-storage-http-") as directory:
        root = Path(directory)
        state = root / "state.json"
        admin, viewer = secrets.token_hex(24), secrets.token_hex(24)
        tokens = root / "tokens.csv"
        tokens.write_text(f'{viewer},viewer,viewer,"readers"\n')
        tokens.chmod(0o600)
        env = dict(PATH=os.environ.get("PATH", ""), HOME=directory,
                   ROYAK_STATE=str(state), ROYAK_DATA_DIR=str(root / "data"),
                   ROYAK_NO_DOCKER="1", DOCKER_HOST="unix://" + str(root / "missing.sock"),
                   ROYAK_TOKEN=admin, ROYAK_TOKEN_FILE=str(tokens))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"https://localhost:{port}"
        server, log, context = None, None, None
        opener = None

        def check(name, value, **details):
            checks.append(dict(name=name, passed=bool(value), **details))
            assert value, name

        def api(path, method="GET", body=None, token=None, stream=False, raw=False):
            request = urllib.request.Request(base + path,
                None if body is None else body.encode() if raw else json.dumps(body).encode(),
                {"Authorization": "Bearer " + (admin if token is None else token),
                 "Content-Type": "application/json"}, method=method)
            try:
                response = opener.open(request, timeout=8)
                if stream:
                    return response
                with response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, json.loads(error.read())

        def stop():
            nonlocal server, log
            if server:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                launches[-1]["reaped"] = server.poll() is not None
                server = None
            if log:
                log.close()
                log = None

        def start():
            nonlocal server, log, context, opener
            log = (root / "server.log").open("ab")
            server = subprocess.Popen([str(binary), "watch", "--tls", "--port", str(port),
                "--ingress-port", "0", "--interval", "1"], env=env, cwd=root,
                stdout=log, stderr=subprocess.STDOUT)
            launches.append(dict(pid=server.pid, started=time.time(), reaped=False))
            deadline = time.monotonic() + 20
            ca = root / ".kube" / "royak-ca.pem"
            while time.monotonic() < deadline:
                assert server.poll() is None, "isolated server exited during startup"
                if ca.exists():
                    context = ssl.create_default_context(cafile=str(ca))
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                        urllib.request.HTTPSHandler(context=context))
                    try:
                        if api("/version")[0] == 200:
                            return
                    except (OSError, ValueError):
                        pass
                time.sleep(.1)
            raise AssertionError("isolated HTTPS API did not become ready")

        def obj(kind, name, ns=None, spec=None, **extra):
            value = dict(apiVersion="v1", kind=kind,
                         metadata=dict(name=name, uid="untrusted-client-uid"), **extra)
            if ns:
                value["metadata"]["namespace"] = ns
            if spec is not None:
                value["spec"] = spec
            return value

        def post(path, body):
            status, response = api(path, "POST", body)
            assert status == 201, f"{body['kind']} apply returned {status}: {response.get('message','')}"
            return response["metadata"]["uid"]

        def claim(ns, name="data", storage_class=None):
            spec = dict(resources=dict(requests=dict(storage="16Mi")), accessModes=["ReadWriteOnce"])
            if storage_class:
                spec["storageClassName"] = storage_class
            return obj("PersistentVolumeClaim", name, ns, spec)

        def pvc(ns, name="data"):
            return f"/api/v1/namespaces/{ns}/persistentvolumeclaims/{name}"

        def snapshot():
            # Runtime node census is not durable storage authority. Compare
            # the exact desired-state document, not wall-clock process output.
            return json.loads(state.read_bytes())["state"]

        def host_access_checks(a_uid):
            role_path='/apis/rbac.authorization.k8s.io/v1/namespaces/a/'
            cluster='/apis/rbac.authorization.k8s.io/v1/'
            post(role_path+'roles',obj('Role','workload-creator','a',rules=[dict(apiGroups=[''],resources=['pods','deployments','statefulsets'],verbs=['create','update','patch'])]))
            post(role_path+'rolebindings',obj('RoleBinding','creator','a',roleRef=dict(apiGroup='rbac.authorization.k8s.io',kind='Role',name='workload-creator'),subjects=[dict(kind='User',name='viewer')]))
            def workload(name,host=False,cap=False,path='/srv/royak-qualification-app'):
                pod=dict(containers=[dict(name='main',image='busybox:1.36',command=['sleep','600'])])
                if host:
                    pod['volumes']=[dict(name='data',hostPath=dict(path=path))]
                    pod['containers'][0]['volumeMounts']=[dict(name='data',mountPath='/app/data')]
                if cap:pod['containers'][0]['securityContext']=dict(capabilities=dict(add=['SYS_ADMIN']))
                return obj('Pod',name,'a',pod)
            check('namespace workload creator can submit an ordinary Pod',api('/api/v1/namespaces/a/pods','POST',workload('ordinary'),token=viewer)[0]==201)
            for label,body in [('hostPath',workload('hostpath',host=True)),('dangerous capability',workload('hostcap',cap=True))]:
                before=snapshot()
                check(label+' requires an additional cluster permission',api('/api/v1/namespaces/a/pods','POST',body,token=viewer)[0]==403 and snapshot()==before)
            vct=obj('StatefulSet','legacy-sts','a',dict(template=dict(spec=dict(containers=[dict(name='main',image='busybox:1.36',volumeMounts=[dict(name='data',mountPath='/data')])])),volumeClaimTemplates=[dict(metadata=dict(name='data'))]))
            before=snapshot()
            check('legacy raw-directory StatefulSet templates require host permission',api('/apis/apps/v1/namespaces/a/statefulsets','POST',vct,token=viewer)[0]==403 and snapshot()==before)
            forged=workload('forged',host=True)
            forged['spec']['containers'][0]['host_access']=dict(version=1,phase='desired',namespace_uid=a_uid,binding_sha256='0'*64)
            before=snapshot()
            check('client-supplied host permit cannot authorize a workload',api('/api/v1/namespaces/a/pods','POST',forged,token=viewer)[0]==403 and snapshot()==before)
            post(cluster+'clusterroles',obj('ClusterRole','host-operator',rules=[dict(apiGroups=[''],resources=['hostaccess'],verbs=['use'])]))
            post(role_path+'rolebindings',obj('RoleBinding','scoped-host','a',roleRef=dict(apiGroup='rbac.authorization.k8s.io',kind='ClusterRole',name='host-operator'),subjects=[dict(kind='User',name='viewer')]))
            before=snapshot()
            check('namespaced binding cannot grant cluster host access',api('/api/v1/namespaces/a/pods','POST',workload('hostpath',host=True),token=viewer)[0]==403 and snapshot()==before)
            post(cluster+'clusterrolebindings',obj('ClusterRoleBinding','host-global',roleRef=dict(apiGroup='rbac.authorization.k8s.io',kind='ClusterRole',name='host-operator'),subjects=[dict(kind='User',name='viewer')]))
            check('explicit cluster host grant permits the exact hostPath workload',api('/api/v1/namespaces/a/pods','POST',workload('hostpath',host=True),token=viewer)[0]==201)
            check('explicit cluster host grant permits the modelled capability',api('/api/v1/namespaces/a/pods','POST',workload('hostcap',cap=True),token=viewer)[0]==201)
            check('explicit operator grant readmits the legacy StatefulSet without claiming native storage',api('/apis/apps/v1/namespaces/a/statefulsets','POST',vct,token=viewer)[0]==201 and snapshot()['deployments']['a/legacy-sts']['containers'][0]['host_access']['namespace_uid']==a_uid)
            permits=[snapshot()['deployments']['a/'+n]['containers'][0]['host_access'] for n in ['hostpath','hostcap']]
            check('persisted permits bind the server namespace incarnation and distinct exact specs',all(p['namespace_uid']==a_uid and p['version']==1 and p['phase']=='desired' and len(p['binding_sha256'])==64 for p in permits) and permits[0]['binding_sha256']!=permits[1]['binding_sha256'])
            other=workload('hostpath',host=True);other['metadata']['namespace']='b';before=snapshot()
            check('host grant alone grants no workload rights in another namespace',api('/api/v1/namespaces/b/pods','POST',other,token=viewer)[0]==403 and snapshot()==before)
            for path in ['/','/var/lib/royak/storage/pools','/var/run/docker.sock','/dev']:
                before=snapshot()
                check('host grant cannot publish reserved path '+path,api('/api/v1/namespaces/a/pods','POST',workload('reserved',host=True,path=path),token=viewer)[0]==400 and snapshot()==before)
            unsupported=workload('host-network');unsupported['spec']['hostNetwork']=True;before=snapshot()
            check('host namespace request is refused rather than silently downgraded',api('/api/v1/namespaces/a/pods','POST',unsupported,token=viewer)[0]==400 and snapshot()==before)
            stop()
            before=state.read_bytes()
            if old_identity_binary:
                destination=root/'schema4-host-reader.json'
                result=subprocess.run([str(old_identity_binary),'backup',str(destination)],env=env,cwd=root,capture_output=True,timeout=10)
                check('actual schema4 binary refuses persisted host permits without mutation',result.returncode!=0 and b'schema' in result.stderr and not destination.exists() and state.read_bytes()==before)
            start()
            check('restart preserves exact host permits and current schema7',json.loads(state.read_bytes())['schemaVersion']==7 and [snapshot()['deployments']['a/'+n]['containers'][0]['host_access'] for n in ['hostpath','hostcap']]==permits)
            check('global host grant revocation is committed',api(cluster+'clusterrolebindings/host-global','DELETE')[0]==200)
            before=snapshot()
            check('revoked host grant cannot update an existing privileged template',api('/api/v1/namespaces/a/pods/hostpath','PUT',workload('hostpath',host=True),token=viewer)[0]==403 and snapshot()==before)
            documents='kind: Pod\nmetadata: {name: must-not-commit, namespace: a}\nspec:\n  containers: [{name: main, image: "busybox:1.36"}]\n---\nkind: Pod\nmetadata: {name: denied-host, namespace: a}\nspec:\n  containers: [{name: main, image: "busybox:1.36", volumeMounts: [{name: data, mountPath: /app}]}]\n  volumes: [{name: data, hostPath: {path: /srv/royak-qualification-app}}]\n'
            code,response=api('/api/v1/namespaces/a/pods','POST',documents,token=viewer,raw=True)
            check('mixed ordinary and denied host workloads fail atomically',code==403 and snapshot()==before,observed_status=code)
            api(role_path+'rolebindings/creator','DELETE');api(role_path+'rolebindings/scoped-host','DELETE')
            api(role_path+'roles/workload-creator','DELETE');api(cluster+'clusterroles/host-operator','DELETE')

        try:
            start()
            check("verified self-signed TLS with hostname verification", context.check_hostname
                  and context.verify_mode == ssl.CERT_REQUIRED)
            check("anonymous access to volume state is refused", api("/api/v1/persistentvolumes", token="invalid")[0] == 401)
            a_uid = post("/api/v1/namespaces", obj("Namespace", "a"))
            b_uid = post("/api/v1/namespaces", obj("Namespace", "b"))
            check("namespace UIDs are server-owned and distinct", len(a_uid) == len(b_uid) == 32
                  and a_uid != b_uid and a_uid != "untrusted-client-uid")
            host_access_checks(a_uid)
            data_path = root / "retained-volume"
            data_path.mkdir()
            sentinel = data_path / "acknowledged-data"
            sentinel.write_bytes(b"must remain across metadata delete/recreate\n")
            sentinel_hash = sha(sentinel)
            pv_uid = post("/api/v1/persistentvolumes", obj("PersistentVolume", "disk", spec=dict(
                capacity=dict(storage="32Mi"), accessModes=["ReadWriteOnce"], hostPath=dict(path=str(data_path)))))
            c_uid = post("/api/v1/namespaces/a/persistentvolumeclaims", claim("a"))
            other_uid = post("/api/v1/namespaces/b/persistentvolumeclaims", claim("b"))
            c = api(pvc("a"))[1]
            check("claim UID, namespace incarnation and reciprocal volume binding persist", c["metadata"]["uid"] == c_uid
                  and c["metadata"]["annotations"]["royak.io/namespace-uid"] == a_uid
                  and c["spec"]["volumeName"] == "disk" and snapshot()["pvs"]["disk"]["bound_to"] == "a/data")
            check("same-name claim in another namespace cannot steal binding", api(pvc("b"))[1]["status"]["phase"] == "Pending"
                  and c_uid != other_uid)
            check("reapply preserves server-owned identities", post("/api/v1/namespaces/a/persistentvolumeclaims", claim("a")) == c_uid
                  and post("/api/v1/namespaces", obj("Namespace", "a")) == a_uid)
            role_path = "/apis/rbac.authorization.k8s.io/v1/namespaces/a/"
            def grant_reader():
                post(role_path + "roles", obj("Role", "storage-reader", "a", rules=[dict(
                    apiGroups=[""], resources=["persistentvolumeclaims"], verbs=["get", "list", "watch"])]))
                post(role_path + "rolebindings", obj("RoleBinding", "reader", "a",
                    roleRef=dict(apiGroup="rbac.authorization.k8s.io", kind="Role", name="storage-reader"),
                    subjects=[dict(kind="User", name="viewer")]))
            grant_reader()
            check("scoped reader sees only granted namespace claims", api(pvc("a"), token=viewer)[0] == 200
                  and api(pvc("b"), token=viewer)[0] == 403
                  and api("/api/v1/persistentvolumes", token=viewer)[0] == 403
                  and api(pvc("a"), "DELETE", token=viewer)[0] == 403)
            listed = api("/api/v1/namespaces/a/persistentvolumeclaims", token=viewer)[1]["items"]
            check("namespace list returns exact stored UID", len(listed) == 1 and listed[0]["metadata"]["uid"] == c_uid)
            with api("/api/v1/namespaces/a/persistentvolumeclaims?watch=true", token=viewer, stream=True) as response:
                event = json.loads(response.readline())
            check("real watch emits server-owned claim UID", event["type"] == "ADDED"
                  and event["object"]["metadata"]["uid"] == c_uid)
            before = snapshot()
            check("claimed PV deletion returns conflict without mutation", api("/api/v1/persistentvolumes/disk", "DELETE")[0] == 409
                  and snapshot() == before and sha(sentinel) == sentinel_hash)
            backup = root / "live-backup.json"
            result = subprocess.run([str(binary), "backup", str(backup)], env=env, cwd=root,
                capture_output=True, timeout=10)
            check("offline backup refuses a live owner", result.returncode != 0 and not backup.exists())
            ca_hash = sha(root / ".kube" / "royak-ca.pem")
            stop()
            start()
            check("restart preserves namespace, claim, PV and TLS identities", api(pvc("a"))[1]["metadata"]["uid"] == c_uid
                  and api("/api/v1/namespaces/a")[1]["metadata"]["uid"] == a_uid
                  and api("/api/v1/persistentvolumes/disk")[1]["metadata"]["uid"] == pv_uid
                  and sha(root / ".kube" / "royak-ca.pem") == ca_hash)
            check("restart preserves namespace-scoped rights", api(pvc("a"), token=viewer)[0] == 200
                  and api(pvc("b"), token=viewer)[0] == 403)
            with api("/api/v1/namespaces/a/persistentvolumeclaims?watch=true", token=viewer, stream=True) as response:
                json.loads(response.readline())
                check("reader binding revocation is committed", api(role_path + "rolebindings/reader", "DELETE")[0] == 200
                      and api(pvc("a"), token=viewer)[0] == 403)
                event = response.readline()
                check("already-open watch closes after RBAC revocation", not event or json.loads(event).get("type") == "ERROR")
            grant_reader()
            check("Retain claim deletion leaves released data", api(pvc("a"), "DELETE")[0] == 200
                  and api("/api/v1/persistentvolumes/disk")[1]["status"]["phase"] == "Released"
                  and sha(sentinel) == sentinel_hash)
            c_new = post("/api/v1/namespaces/a/persistentvolumeclaims", claim("a"))
            check("same-name claim recreation cannot inherit predecessor volume", c_new != c_uid
                  and api(pvc("a"))[1]["status"]["phase"] == "Pending")
            old_watch = api("/api/v1/namespaces/a/persistentvolumeclaims?watch=true", token=viewer, stream=True)
            json.loads(old_watch.readline())
            check("namespace deletion removes claims and former grants", api("/api/v1/namespaces/a", "DELETE")[0] == 200
                  and api(pvc("a"), token=viewer)[0] == 403 and sha(sentinel) == sentinel_hash)
            a_new = post("/api/v1/namespaces", obj("Namespace", "a"))
            post("/api/v1/namespaces/a/persistentvolumeclaims", claim("a"))
            check("new namespace incarnation cannot inherit old rights or identity", a_new != a_uid
                  and api(pvc("a"))[1]["metadata"]["annotations"]["royak.io/namespace-uid"] == a_new
                  and api(pvc("a"), token=viewer)[0] == 403)
            grant_reader()
            check("explicit regrant allows only a new namespace request", api(pvc("a"), token=viewer)[0] == 200)
            try:
                remaining = old_watch.readline()
                closed_safely = not remaining or json.loads(remaining).get("type") == "ERROR"
            finally:
                old_watch.close()
            check("already-open watch cannot observe replacement namespace after grant removal", closed_safely)
            post("/apis/storage.k8s.io/v1/storageclasses", obj("StorageClass", "unsafe-delete", spec=dict(
                hostPathPrefix=str(root / "legacy-delete"), reclaimPolicy="Delete")))
            post("/api/v1/namespaces/b/persistentvolumeclaims", claim("b", "danger", "unsafe-delete"))
            before = snapshot()
            check("legacy destructive reclaim and namespace cascade fail atomically", api(pvc("b", "danger"), "DELETE")[0] == 409
                  and api("/api/v1/namespaces/b", "DELETE")[0] == 409 and snapshot() == before
                  and sha(sentinel) == sentinel_hash)
            post("/apis/storage.k8s.io/v1/storageclasses", obj("StorageClass", "replicated", spec=dict(
                provisioner="royak/drbd-lvm", reclaimPolicy="Delete")))
            managed = claim("b", "replicated", "replicated")
            managed["status"] = dict(phase="Bound", royakStorage=dict(phase="Attached", attachmentEpoch=99))
            managed_uid = post("/api/v1/namespaces/b/persistentvolumeclaims", managed)
            current = api(pvc("b", "replicated"))[1]
            managed_pv = current["spec"]["volumeName"]
            volume_uid = current["status"]["royakStorage"]["volumeUID"]
            check("managed claim reserves an unwritable intent, not user-supplied attachment authority",
                  current["metadata"]["uid"] == managed_uid and current["status"]["phase"] == "Pending"
                  and current["status"]["royakStorage"]["phase"] == "PendingProvision"
                  and current["status"]["royakStorage"]["attachmentEpoch"] == 0
                  and current["status"]["royakStorage"]["assignment"] is None)
            physical = api("/api/v1/persistentvolumes/" + managed_pv)[1]
            check("unprovisioned managed PV has no host path and does not claim readiness",
                  physical["status"]["phase"] == "Pending" and "hostPath" not in physical["spec"]
                  and snapshot()["pvs"][managed_pv]["host_path"] == ""
                  and physical["metadata"]["uid"] == volume_uid)
            check("managed class cannot disappear behind its lifecycle", api("/apis/storage.k8s.io/v1/storageclasses/replicated", "DELETE")[0] == 409)
            for label, body, path in (
                ("managed class refuses arbitrary host path", obj("StorageClass", "adopt", spec=dict(
                    provisioner="royak/drbd-lvm", hostPathPrefix=str(data_path))), "/apis/storage.k8s.io/v1/storageclasses"),
                ("managed PV cannot adopt existing data", obj("PersistentVolume", "adopt", spec=dict(
                    storageClassName="replicated", hostPath=dict(path=str(data_path)))), "/api/v1/persistentvolumes"),
                ("managed shared-write mode is refused", obj("PersistentVolumeClaim", "rwx", "b", dict(
                    storageClassName="replicated", accessModes=["ReadWriteMany"])), "/api/v1/namespaces/b/persistentvolumeclaims"),
            ):
                before = snapshot()
                check(label, api(path, "POST", body)[0] == 400 and snapshot() == before and sha(sentinel) == sentinel_hash)
            post("/api/v1/namespaces/a/persistentvolumeclaims", claim("a", "native-cancel", "replicated"))
            cancelled = api(pvc("a", "native-cancel"), token=viewer)[1]["status"]["royakStorage"]["volumeUID"]
            check("namespace-scoped view of managed intent stays isolated", api(pvc("b", "replicated"), token=viewer)[0] == 403
                  and api(pvc("a", "native-cancel"), token=viewer)[0] == 200)
            check("unstarted managed intent can cancel without backend/data cleanup", api(pvc("a", "native-cancel"), "DELETE")[0] == 200
                  and snapshot()["storage_identities"]["lifecycle"]["volumes"][cancelled]["phase"] == "Deleted"
                  and sha(sentinel) == sentinel_hash)
            stop()
            start()
            check("restart preserves exact managed intent without silently provisioning it", api(pvc("b", "replicated"))[1]["status"]["royakStorage"]["volumeUID"] == volume_uid
                  and api(pvc("b", "replicated"))[1]["status"]["royakStorage"]["phase"] == "PendingProvision")
            stop()
            backup = root / "offline-backup.json"
            result = subprocess.run([str(binary), "backup", str(backup)], env=env, cwd=root,
                capture_output=True, timeout=10)
            check("offline export retains current schema-7 identities", result.returncode == 0
                  and json.loads(backup.read_bytes())["schemaVersion"] == 7
                  and json.loads(backup.read_bytes())["state"]["storage_identities"] == snapshot()["storage_identities"])
            if old_binary:
                before = state.read_bytes()
                target = root / "old-reader-backup.json"
                result = subprocess.run([str(old_binary), "backup", str(target)], env=env, cwd=root,
                    capture_output=True, timeout=10)
                check("previous binary refuses new schema without data mutation", result.returncode != 0
                      and not target.exists() and state.read_bytes() == before)
            if old_identity_binary:
                before = state.read_bytes()
                target = root / "old-schema4-reader-backup.json"
                result = subprocess.run([str(old_identity_binary), "backup", str(target)], env=env, cwd=root,
                    capture_output=True, timeout=10)
                check("previous schema4 binary refuses schema7 authority", result.returncode != 0
                      and b"schema" in result.stderr and not target.exists() and state.read_bytes() == before)
            ordinary = root / "ordinary-old-state.json"
            ordinary.write_text(json.dumps(dict(schemaVersion=1, namespaces=["default"])))
            before = state.read_bytes()
            result = subprocess.run([str(binary), "restore", str(ordinary)], env=env, cwd=root,
                capture_output=True, timeout=10)
            check("legacy restore cannot discard current managed lifecycle", result.returncode != 0 and state.read_bytes() == before)
            target = root / "import-target.json"
            result = subprocess.run([str(binary), "restore", str(backup)], env=dict(env, ROYAK_STATE=str(target)),
                cwd=root, capture_output=True, timeout=10)
            check("legacy restore cannot resurrect exported attachment authority", result.returncode != 0 and not target.exists())
            for variant in ("missing lifecycle", "lowered schema"):
                malformed = json.loads(backup.read_bytes())
                if variant == "missing lifecycle":
                    malformed["state"]["storage_identities"].pop("lifecycle")
                else:
                    malformed["schemaVersion"] = 3
                source = root / (variant.replace(" ", "-") + ".json")
                source.write_text(json.dumps(malformed))
                original = source.read_bytes()
                destination = source.with_suffix(".backup.json")
                result = subprocess.run([str(binary), "backup", str(destination)],
                    env=dict(env, ROYAK_STATE=str(source)), cwd=root, capture_output=True, timeout=10)
                check("loaded managed state refuses " + variant, result.returncode != 0
                      and not destination.exists() and source.read_bytes() == original)
            seed = root / "seed-probe.json"
            seed.write_bytes(before)
            result = subprocess.run([str(binary), "watch", "--tls", "--port", str(port), "--ingress-port", "0",
                "--node-id", "99", "--bootstrap"], env=dict(env, ROYAK_STATE=str(seed), ROYAK_CLUSTER_SECRET=secrets.token_hex(32)),
                cwd=root, capture_output=True, timeout=12)
            check("fresh Raft bootstrap cannot import managed authority from a seed", result.returncode != 0
                  and b"managed volume or host-access state requires explicit recovery" in result.stderr
                  and seed.read_bytes() == before, observed_exit_code=result.returncode,
                  stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
            check("retained data survived all metadata operations", sha(sentinel) == sentinel_hash)
        except Exception as error:
            checks.append(dict(name="fixture completion", passed=False, error=f"{type(error).__name__}: {error}"))
        finally:
            stop()
        checks.append(dict(name="all exact server processes reaped", passed=all(row["reaped"] for row in launches)))
    return checks, launches


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--old-binary", type=Path)
    p.add_argument("--old-identity-binary", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    if a.output.exists():
        p.error("never overwrite earlier evidence")
    binary = a.binary.resolve()
    checks, launches = collect(binary, a.old_binary.resolve() if a.old_binary else None,
                              a.old_identity_binary.resolve() if a.old_identity_binary else None)
    source = Path(__file__).resolve().parents[2] / "src"
    report = dict(passed=all(c["passed"] for c in checks), checks=checks, launches=launches,
        binary_sha256=sha(binary), fixture_sha256=sha(Path(__file__)),
        source_sha256={str(path.relative_to(source)): sha(path) for path in sorted(source.rglob("*")) if path.is_file()},
        scope="native single-node HTTPS identity/RBAC/unwritable managed-intent/restart/delete contract; no actual storage-driver IO or physical fencing")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(dict(passed=report["passed"], checks=checks, binary_sha256=report["binary_sha256"]), indent=2))
    raise SystemExit(not report["passed"])


if __name__ == "__main__":
    main()
