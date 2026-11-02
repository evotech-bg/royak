"""Actual API/Docker regressions; run by test-beta-lifecycle-topology.sh only."""
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error

URL = sys.argv[1]
NS = "ci-beta"
OTHER = "ci-beta-other"
ADMIN = os.environ["ADMIN_TOKEN"]
VIEW = os.environ["VIEW_TOKEN"]
TLS = ssl._create_unverified_context()  # ephemeral loopback-only test server
passed = 0

def check(name, condition):
    global passed
    if not condition:
        raise AssertionError(name)
    passed += 1
    print("  ✓ " + name, flush=True)

def api(path, method="GET", body=None, token=ADMIN):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type":"application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(URL + path, data, headers, method=method)
    try:
        with urllib.request.urlopen(request, context=TLS, timeout=25) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.loads(error.read())

def docker(*args, must=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=15)
    if must and result.returncode:
        raise RuntimeError("Docker fixture command failed: " + " ".join(args[:3]))
    return result.stdout.strip()

def wait(function, name, timeout=35):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = function()
        if result:
            return result
        time.sleep(.15)
    raise AssertionError("Timed out: " + name)

def apply(kind, name, spec=None, namespace=NS, **fields):
    groups = {"Deployment":("apps/v1","deployments"), "DaemonSet":("apps/v1","daemonsets"), "Job":("batch/v1","jobs"), "CronJob":("batch/v1","cronjobs"), "RoleBinding":("rbac.authorization.k8s.io/v1","rolebindings")}
    version, resource = groups.get(kind, ("v1", {"Namespace":"namespaces","Secret":"secrets","ConfigMap":"configmaps"}[kind] if kind in ("Namespace","Secret","ConfigMap") else ""))
    metadata = {"name":name}
    if kind != "Namespace":
        metadata["namespace"] = namespace
    body = dict(apiVersion=version, kind=kind, metadata=metadata, **fields)
    if spec is not None:
        body["spec"] = spec
    base = "/api/v1" if version == "v1" else "/apis/" + version
    path = base + ("" if kind == "Namespace" else "/namespaces/" + namespace) + "/" + resource
    code, _ = api(path, "POST", body)
    assert code in (200,201), (kind, code)

def deploy(name, probes, main="", namespace=NS, secret=False):
    command = "cut -d' ' -f1 /proc/uptime > /tmp/start; : > /tmp/checks; " + main + "; exec sleep 3600"
    c = dict(name="main", image="alpine:3.22", command=["sh","-c",command], **probes)
    if secret:
        c["envFrom"] = [{"secretRef":{"name":"credentials"}}]
    apply("Deployment", name, {"replicas":1,"template":{"spec":{"containers":[c]}}}, namespace)
    return wait(lambda: docker("ps","-q","--filter","label=royak.namespace=" + namespace,
                               "--filter","label=royak.deployment=" + name), "container " + name)

def records(container, file="checks"):
    raw = docker("exec",container,"cat","/tmp/" + file,must=False)
    return [line.split() for line in raw.splitlines() if line.strip()]

def ready(name):
    code, data = api("/api/v1/namespaces/" + NS + "/pods")
    assert code == 200
    for p in data["items"]:
        if p["metadata"]["labels"].get("app") != name:
            continue
        status = p["status"]
        reported = any(c.get("ready") is True for c in status.get("containerStatuses",[]))
        assert any(c.get("type") == "Ready" and c.get("status") == ("True" if reported else "False") for c in status.get("conditions",[])), "Ready condition agrees with readiness"
        if reported:
            return True
    return False

def started(container):
    return docker("inspect","-f","{{.State.StartedAt}}",container)

def probe(file="checks", marker="pass"):
    return {"exec":{"command":["sh","-c", f"now=$(cut -d' ' -f1 /proc/uptime); if test -e /tmp/{marker}; then echo \"$now pass\" >> /tmp/{file}; exit 0; else echo \"$now fail\" >> /tmp/{file}; exit 1; fi"]},
            "initialDelaySeconds":6,"periodSeconds":2,"failureThreshold":3,"successThreshold":2,"timeoutSeconds":1}

def main():
    for namespace in (NS,OTHER):
        apply("Namespace",namespace)
    apply("Secret","credentials",stringData={"value":"NEVER_EXPORT_THIS_SECRET"})
    apply("RoleBinding","read-only",roleRef={"kind":"ClusterRole","name":"view"},subjects=[{"kind":"Group","name":"viewers"}])
    c = deploy("readiness", {"readinessProbe":probe()}, "true", secret=True)
    initial_start = started(c)
    first = wait(lambda: records(c), "first readiness check")
    origin = float(docker("exec",c,"cat","/tmp/start"))
    check("readiness initialDelaySeconds is honored",float(first[0][0]) - origin >= 5.8)
    check("failed initial readiness does not become ready",not ready("readiness"))
    docker("exec",c,"touch","/tmp/pass")
    wait(lambda: ready("readiness"), "two readiness successes")
    recent = records(c)
    check("successThreshold requires consecutive successes",len(recent) >= 2 and all(r[1] == "pass" for r in recent[-2:]))
    check("periodSeconds controls actual probe frequency",all(float(b[0])-float(a[0]) >= 1.8 for a,b in zip(recent,recent[1:])))
    docker("exec",c,"rm","/tmp/pass")
    wait(lambda: records(c)[-1][1] == "fail", "first readiness failure")
    check("one failed readiness check does not remove a healthy endpoint",ready("readiness"))
    wait(lambda: not ready("readiness"), "readiness failure threshold")
    check("failureThreshold reached before NotReady",all(r[1] == "fail" for r in records(c)[-3:]))
    check("readiness failure does not restart application",started(c) == initial_start)

    # Same names in another namespace cannot leak through topology scope.
    deploy("readiness", {}, "true", namespace=OTHER)
    check("topology refuses anonymous access",api("/royak/v1/topology",token=None)[0] == 401)
    check("namespace viewer cannot list cluster-wide topology",api("/royak/v1/topology",token=VIEW)[0] == 403)
    check("namespace viewer cannot inspect another namespace",api("/royak/v1/topology?namespace=" + OTHER,token=VIEW)[0] == 403)
    for resource in ("namespaces","nodes","persistentvolumes"):
        check("namespaced URL cannot smuggle cluster-scoped " + resource, api("/api/v1/namespaces/" + NS + "/" + resource,token=VIEW)[0] == 400)
    code, graph = api("/royak/v1/topology?namespace=" + NS,token=VIEW)
    check("namespace viewer receives permitted topology",code == 200 and graph["read_only"])
    check("topology contains no foreign namespace resources",all(n["namespace"] in (NS,"") for n in graph["nodes"]))
    check("secret reference is Unknown without secret-list permission",any(n["kind"] == "Secret" and n["status"] == "Unknown" for n in graph["nodes"]))
    _, admin_graph = api("/royak/v1/topology?namespace=" + NS)
    check("secret values never enter topology even for admin","NEVER_EXPORT_THIS_SECRET" not in json.dumps(admin_graph))
    check("observed placement edges are present",any(e["relation"] == "runs on" and e["evidence"] == "observed placement" for e in graph["edges"]))

    live = probe(marker="live"); live.update(initialDelaySeconds=4,successThreshold=1)
    c = deploy("liveness",{"livenessProbe":live},"touch /tmp/live")
    before = started(c)
    wait(lambda: records(c),"first liveness check")
    check("liveness initial delay is honored",float(records(c)[0][0])-float(docker("exec",c,"cat","/tmp/start")) >= 3.8)
    for attempt in range(2):
        docker("exec",c,"rm","-f","/tmp/live")
        def two_failures():
            r = records(c)
            return len(r) >= 2 and all(x[1] == "fail" for x in r[-2:])
        wait(two_failures,"two liveness failures")
        check("liveness tolerates failures below threshold, pass " + str(attempt+1),started(c) == before)
        if attempt == 0:
            docker("exec",c,"touch","/tmp/live")
            wait(lambda: records(c)[-1][1] == "pass","recovered liveness clears failure streak")
    wait(lambda: started(c) != before,"liveness restart at threshold")
    check("liveness threshold restarts the container",True)
    time.sleep(1)
    check("restart of same ID resets probe delay/counters",not records(c))

    start_probe = probe("startup-checks","gate")
    start_probe.update(initialDelaySeconds=1,periodSeconds=1,failureThreshold=30,successThreshold=1)
    read_probe = probe("ready-checks")
    read_probe.update(initialDelaySeconds=3,periodSeconds=1,failureThreshold=1,successThreshold=1)
    live_probe = probe("live-checks")
    live_probe.update(initialDelaySeconds=4,periodSeconds=1,successThreshold=1)
    c = deploy("startup",{"startupProbe":start_probe,"readinessProbe":read_probe,"livenessProbe":live_probe},
               ": > /tmp/startup-checks; : > /tmp/ready-checks; : > /tmp/live-checks; touch /tmp/pass")
    wait(lambda: records(c,"startup-checks"),"startup first failure")
    check("startup gate blocks readiness and liveness",not records(c,"ready-checks") and not records(c,"live-checks"))
    docker("exec",c,"touch","/tmp/gate")
    wait(lambda: ready("startup"),"readiness after startup success")
    success = float(next(r[0] for r in records(c,"startup-checks") if r[1] == "pass"))
    check("readiness delay begins after startup succeeds",float(records(c,"ready-checks")[0][0]) - success >= 2.8)
    wait(lambda: records(c,"live-checks"),"liveness after startup success")
    check("liveness delay begins after startup succeeds",float(records(c,"live-checks")[0][0]) - success >= 3.8)

    failing_start = probe("startup-failures","never-created")
    failing_start.update(initialDelaySeconds=3,periodSeconds=2,failureThreshold=2,successThreshold=1)
    c = deploy("startup-restart",{"startupProbe":failing_start},": > /tmp/startup-failures")
    before = started(c)
    wait(lambda: records(c,"startup-failures"),"first failed startup check")
    check("startup failure below threshold does not restart",started(c)==before)
    check("failed startup remains NotReady",not ready("startup-restart"))
    wait(lambda: started(c)!=before,"startup restart at failure threshold")
    check("startup failure threshold restarts the actual container",True)
    time.sleep(1)
    check("startup restart resets its initial delay and counters",not records(c,"startup-failures"))
    api("/apis/apps/v1/namespaces/"+NS+"/deployments/startup-restart","DELETE")

    hung = {"exec":{"command":["sh","-c","touch /tmp/probe-began; (sleep 3; touch /tmp/late-write) & wait"]},
            "initialDelaySeconds":0,"periodSeconds":10,"failureThreshold":1,"timeoutSeconds":1}
    c = deploy("hung",{"readinessProbe":hung},"true")
    before = started(c)
    wait(lambda: docker("exec",c,"sh","-c","test -e /tmp/probe-began && echo yes",must=False),"hung probe started")
    time.sleep(3.3)
    check("timed-out exec and grandchild cannot perform a late write",docker("exec",c,"sh","-c","test ! -e /tmp/late-write && echo clean") == "clean")
    check("timed-out readiness probe does not restart application",started(c) == before)
    check("timed-out readiness fails closed",not ready("hung"))

    # Every regular container participates, including sidecars. Restart is
    # container-local; disappearance is healed as a whole pod after launch grace.
    side_probe = {"exec":{"command":["test","-e","/tmp/pass"]},"periodSeconds":1,"failureThreshold":1,"timeoutSeconds":1}
    side_live = {"exec":{"command":["test","-e","/tmp/live"]},"periodSeconds":1,"failureThreshold":2,"timeoutSeconds":1}
    apply("Deployment","sidecars",{"replicas":1,"template":{"spec":{"containers":[
        {"name":"main","image":"alpine:3.22","command":["sleep","3600"]},
        {"name":"agent","image":"alpine:3.22","command":["sh","-c","touch /tmp/live; exec sleep 3600"],"readinessProbe":side_probe,"livenessProbe":side_live}
    ]}}})
    def side_id(role):
        return docker("ps","-q","--filter","label=royak.namespace="+NS,"--filter","label=royak.deployment=sidecars","--filter","label=royak.role="+role)
    main_id = wait(lambda: side_id("main"),"sidecar main")
    agent_id = wait(lambda: side_id("sidecar"),"sidecar agent")
    main_start = started(main_id)
    check("sidecar readiness gates the entire pod",not ready("sidecars"))
    docker("exec",agent_id,"touch","/tmp/pass")
    wait(lambda: ready("sidecars"),"sidecar readiness success")
    check("successful sidecar makes pod Ready",True)
    agent_start = started(agent_id)
    docker("exec",agent_id,"rm","/tmp/live")
    wait(lambda: started(agent_id) != agent_start,"sidecar liveness restart")
    check("sidecar liveness does not restart main",started(main_id) == main_start)
    # An updated template must not retroactively gate an existing ready pod.
    docker("exec",agent_id,"touch","/tmp/pass")
    wait(lambda: ready("sidecars"),"sidecar ready after restart")
    docker("rm","-f",agent_id)
    wait(lambda: side_id("main") and side_id("main") != main_id,"missing sidecar heals pod",timeout=45)
    check("missing sidecar replaces whole pod",bool(wait(lambda: side_id("sidecar") and side_id("sidecar") != agent_id,"sidecar replacement")))
    check("replacement does not inherit sidecar readiness",not ready("sidecars"))

    original = deploy("probe-rollout",{},"true")
    wait(lambda: ready("probe-rollout"),"original rollout pod ready")
    apply("Deployment","probe-rollout",{"replicas":1,"template":{"spec":{"containers":[
        {"name":"main","image":"alpine:3.22","command":["sleep","3600"]},
        {"name":"agent","image":"alpine:3.22","command":["sleep","3600"],"readinessProbe":side_probe}
    ]}}})
    new_agent = wait(lambda: docker("ps","-q","--filter","label=royak.namespace="+NS,"--filter","label=royak.deployment=probe-rollout","--filter","label=royak.role=sidecar"),"new rollout sidecar")
    time.sleep(11) # exceed the missing-sidecar creation grace on the old pod
    check("rollout leaves the original pod running while new sidecar is NotReady",docker("inspect","-f","{{.State.Running}}",original,must=False)=="true")
    check("new sidecar settings do not gate the original pod",ready("probe-rollout"))
    docker("exec",new_agent,"touch","/tmp/pass")
    wait(lambda: not docker("inspect","-f","{{.State.Running}}",original,must=False),"retire old pod after new readiness")
    check("rollout retires old pod only after new pod becomes Ready",ready("probe-rollout"))

    for kind in ("DaemonSet","Job","CronJob"):
        name = "probe-" + kind.lower()
        container = {"name":"worker","image":"alpine:3.22","command":["sleep","3600"],"readinessProbe":side_probe}
        spec = {"template":{"spec":{"containers":[container]}}}
        if kind == "CronJob": spec["schedule"] = "* * * * *"
        apply(kind,name,spec)
        cid = wait(lambda: docker("ps","-q","--filter","label=royak.namespace="+NS,"--filter","label=royak."+kind.lower()+"="+name),kind+" container")
        check(kind+" begins NotReady",not ready(name))
        docker("exec",cid,"touch","/tmp/pass")
        wait(lambda: ready(name),kind+" readiness")
        check(kind+" readiness follows actual probe",True)
        version,plural = ("apps/v1","daemonsets") if kind == "DaemonSet" else ("batch/v1",kind.lower()+"s")
        for field in ("containers","initContainers"):
            podspec = {"containers":[container]}
            extra = {"name":"unmodelled","image":"alpine:3.22","readinessProbe":side_probe}
            if field == "containers": podspec[field] = [container,extra]
            else: podspec[field] = [extra]
            body = {"apiVersion":version,"kind":kind,"metadata":{"name":name,"namespace":NS},"spec":{"template":{"spec":podspec}}}
            code,_ = api("/apis/"+version+"/namespaces/"+NS+"/"+plural,"POST",body)
            check(kind+" refuses probes in unmodelled "+field,code==400)
    print(f"Results: {passed} passed, 0 failed",flush=True)

if __name__ == "__main__":
    try:
        main()
    finally:
        for namespace,name in [(NS,"readiness"),(OTHER,"readiness"),(NS,"liveness"),(NS,"startup"),(NS,"startup-restart"),(NS,"hung"),(NS,"sidecars"),(NS,"probe-rollout")]:
            api(f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}","DELETE")
