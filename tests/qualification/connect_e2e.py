"""Real laptop CLI + three independent Docker daemons + kernel WireGuard.
Never uses the host Docker socket inside nodes or changes the host VPN/routes.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import selectors
import socket
import ssl
import subprocess
import time
import traceback
from run import Lab, docker, request, wait_for, digest, HERE, ROOT, source_inventory

APP = """import os,socket,threading
def serve(c):
 try:
  data=c.recv(65536)
  if data.startswith(b'GET '):
   body=os.environ['MARKER'].encode();c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\nConnection: close\\r\\n\\r\\n'+body);return
  c.sendall(os.environ['MARKER'].encode()+b'\\n')
  while data:c.sendall(data);data=c.recv(65536)
 finally:c.close()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',9090));s.listen()
while True:
 c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
"""

class ConnectLab(Lab):
    def __init__(self,args):
        super().__init__(args)
        self.user=secrets.token_hex(24)
        self.other=secrets.token_hex(24)
        self.viewer=secrets.token_hex(24)
        self.children=[]
        self.sockets=[]
        self.stream_targets={}
        self.iface="rkconn"

    def container(self,name,*args):
        if name.startswith(self.run+"-n"):
            peers={"q-n"+str(i):f"10.246.72.{i}:6443" for i in range(1,4)}
            args=("-e","ROYAK_TOKEN_FILE=/lab/connect-tokens.csv","-e","ROYAK_CONNECT_WG_INTERFACE="+self.iface,
                  "-e","ROYAK_CONNECT_WG_PEERS="+json.dumps(peers),*args)
            args=tuple("--storage-driver=overlay2" if a=="--storage-driver=vfs" else a for a in args)
        return super().container(name,*args)

    def start_node(self,node):
        csv=f'{self.user},alice,u1,"connect-users"\n{self.other},mallory,u2,"connect-users"\n{self.viewer},vera,u3,"viewers"\n'
        docker("exec","-i",node["name"],"sh","-ec","umask 077; dd of=/lab/connect-tokens.csv status=none",input=csv.encode())
        super().start_node(node)

    def wg_setup(self):
        keys={}
        for n in self.nodes:
            docker("exec",n["name"],"apk","add","--no-cache","wireguard-tools","iproute2","gdb",timeout=120)
            keys[n["id"]]=docker("exec",n["name"],"sh","-ec","umask 077; wg genkey > /lab/connect-wg.key; wg pubkey < /lab/connect-wg.key").strip()
            docker("exec",n["name"],"ip","link","add",self.iface,"type","wireguard")
            docker("exec",n["name"],"ip","address","add",f"10.246.72.{n['id']}/24","dev",self.iface)
            docker("exec",n["name"],"wg","set",self.iface,"listen-port","51821","private-key","/lab/connect-wg.key")
        for n in self.nodes:
            for peer in self.nodes:
                if peer==n:continue
                docker("exec",n["name"],"wg","set",self.iface,"peer",keys[peer["id"]],"allowed-ips",f"10.246.72.{peer['id']}/32","endpoint",peer["ip"]+":51821","persistent-keepalive","1")
            docker("exec",n["name"],"ip","link","set",self.iface,"up")
        self.check("three real kernel WireGuard interfaces",all('"info_kind":"wireguard"' in docker("exec",n["name"],"ip","-j","-d","link","show",self.iface).replace(" ","") for n in self.nodes))

    def resource(self,kind,name,spec=None,ns="team-a",**fields):
        groups={"Deployment":("apps/v1","deployments"),"Role":("rbac.authorization.k8s.io/v1","roles"),"RoleBinding":("rbac.authorization.k8s.io/v1","rolebindings")}
        version,plural=groups.get(kind,("v1",{"Namespace":"namespaces","Service":"services"}.get(kind,"")))
        metadata={"name":name}
        if kind!="Namespace":metadata["namespace"]=ns
        body=dict(apiVersion=version,kind=kind,metadata=metadata,**fields)
        if spec is not None:body["spec"]=spec
        base="/api/v1" if version=="v1" else "/apis/"+version
        self.apply(base+("" if kind=="Namespace" else "/namespaces/"+ns)+"/"+plural,body)

    def grant(self,ns="team-a"):
        self.resource("Role","connector",ns=ns,rules=[{"apiGroups":[""],"resources":["services/connect"],"resourceNames":["api:80"],"verbs":["create"]}])
        self.resource("RoleBinding","connector",ns=ns,roleRef={"kind":"Role","name":"connector"},subjects=[{"kind":"Group","name":"connect-users"}])

    def app(self,name,ns="team-a",marker="TEAM_A",ready=True):
        # Positive readiness checks the application socket, not whether an
        # unrelated `true` exec can be scheduled under its CPU quota. The
        # negative rollout deliberately uses a failing probe with a live socket.
        health={"tcpSocket":{"port":9090},"periodSeconds":1,"failureThreshold":1} if ready else {"exec":{"command":["false"]},"periodSeconds":1,"failureThreshold":1}
        self.resource("Deployment",name,{"replicas":1,"template":{"spec":{"containers":[{"name":"app","image":self.image,"ports":[{"containerPort":9090}],"command":["python3","-u","-c",APP],"env":[{"name":"MARKER","value":marker}],"resources":{"limits":{"cpu":"250m","memory":"64Mi"}},"securityContext":{"runAsUser":10001,"runAsNonRoot":True,"readOnlyRootFilesystem":True,"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}},"readinessProbe":health}]}}},ns=ns)

    def cp(self,ns="team-a"):
        return "/royak/v1/connect/namespaces/"+ns+"/sessions"

    def call(self,method,path,body=None,token=None):
        result=request(self.gateway["api"]+path,method,body,self.user if token is None else token,timeout=8)
        if result[0]==0:
            raise RuntimeError(f"gateway transport unavailable: {method} {path} on {self.gateway['name']}")
        return result

    def pods(self,ns):
        code,data=self.api(self.gateway,"GET","/api/v1/namespaces/"+ns+"/pods")
        assert code==200 and isinstance(data,dict) and isinstance(data.get("items"),list),("pod observation failed",ns,code,data)
        return data["items"]

    def service_converged(self,owner):
        for node in self.nodes:
            code,data=self.api(node,"GET","/api/v1/namespaces/team-a/services/api")
            assert code==200 and isinstance(data,dict),("Service observation failed",node["id"],code,data)
            if data.get("spec",{}).get("selector",{}).get("app")!=owner:return False
        return True

    def diagnostics(self):
        evidence=[]
        for node in self.nodes:
            entry={"node":node["id"]}
            try:
                state=json.loads(docker("inspect","-f","{{json .State}}",node["name"]))
                entry["container"]={k:state.get(k) for k in ("Running","OOMKilled","ExitCode","Pid","StartedAt","FinishedAt")}
                entry["resources"]=json.loads(docker("stats","--no-stream","--format","{{json .}}",node["name"],timeout=10))
                entry["process"]=docker("exec",node["name"],"sh","-c",'p=$(cat /lab/royak.pid); if kill -0 "$p" 2>/dev/null; then echo ROYAK_ALIVE; cat /proc/"$p"/wchan; else echo ROYAK_DEAD; fi; for f in /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max; do if test -r "$f"; then echo "$f"; cat "$f"; fi; done',timeout=10)
                entry["api_status"]=self.api(node,"GET","/royak/v1/raft/status",timeout=2)[0]
                if node==getattr(self,"gateway",None):
                    entry["sessions"]=self.api(node,"GET",self.cp(),timeout=2)
                    entry["audit"]=self.api(node,"GET","/royak/v1/connect/namespaces/team-a/audit",timeout=2)
            except Exception as error:entry["diagnostic_error"]=str(error)
            evidence.append(entry)
        text=json.dumps(evidence,indent=2)
        for secret in (self.user,self.other,self.viewer,self.token,self.cluster_secret,self.seal):text=text.replace(secret,"[REDACTED]")
        (self.out/"failure-diagnostics.json").write_text(text)

    def session(self,ttl=60,ns="team-a"):
        def create():
            code,data=self.call("POST",self.cp(ns),dict(service="api",port=80,ttl_seconds=ttl))
            # 421 is a rejection before a grant exists, not an ambiguous write.
            # Keep the explicitly trusted issuer; never silently follow a leader.
            if code==421:return None
            assert code==201,(code,data)
            return data["id"]
        return wait_for(create,"trusted issuer has a fresh quorum lease",timeout=15)

    def stream(self,ident,token=None,ns="team-a",expected=101,allow_unavailable=False):
        context=ssl.create_default_context(cafile=str(self.ca))
        tcp=socket.create_connection(("127.0.0.1",int(self.gateway["api"].rsplit(":",1)[1])),timeout=5)
        s=context.wrap_socket(tcp,server_hostname="127.0.0.1");s.settimeout(5)
        path=self.cp(ns)+"/"+ident+"/stream"
        head=f"GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token or self.user}\r\nConnection: Upgrade\r\nUpgrade: royak-connect-v1\r\n\r\n"
        s.sendall(head.encode());answer=b""
        while not answer.endswith(b"\r\n\r\n"):
            byte=s.recv(1)
            if not byte:break
            answer+=byte
            assert len(answer)<8192
        code=int(answer.split(b" ")[1])
        if code==503 and allow_unavailable:
            # A fresh transport attempt, never replay of application bytes.
            # Recovery is measured by real TCP readiness, not a stale census.
            self.event("connect-prebyte-attempts.jsonl",kind="recovery_connect",http_status=503,application_bytes_sent=0)
            s.close();return None
        if code!=expected:
            length=next((int(h.split(b":",1)[1]) for h in answer.split(b"\r\n") if h.lower().startswith(b"content-length:")),0)
            body=b""
            while len(body)<min(length,4096):
                part=s.recv(min(length-len(body),4096-len(body)))
                if not part:break
                body+=part
            s.close()
            raise AssertionError((code,answer[:80],body))
        if code!=101:s.close();return None
        self.sockets.append(s);self.stream_targets[id(s)]=(ns,ident);return s

    def echo(self,s,marker=b"TEAM_A",payload=None):
        data=payload if payload is not None else bytes(range(256))*4;s.sendall(data)
        got=b""
        while len(got)<len(data)+len(marker)+1:
            part=s.recv(8192)
            if not part:
                ns,ident=self.stream_targets[id(s)]
                status,meta=self.call("GET",self.cp(ns)+"/"+ident)
                raise AssertionError(dict(error="backend closed before binary echo completed",received=len(got),expected=len(data)+len(marker)+1,session_status=status,metadata=meta))
            got+=part
        assert got==marker+b"\n"+data

    def closed(self,s,timeout=5):
        end=time.monotonic()+timeout;s.settimeout(.2)
        while time.monotonic()<end:
            try:
                if s.recv(1024)==b"":return True
            except (socket.timeout,TimeoutError):continue
            except OSError:return True
        return False

    def live(self,s):
        payload=b"still-live-before-fault";s.sendall(payload);got=b"";s.settimeout(3)
        while len(got)<len(payload):
            part=s.recv(len(payload)-len(got));assert part,"connection was already closed before fault"
            got+=part
        assert got==payload

    def reason(self,ident):
        return self.call("GET",self.cp()+"/"+ident)[1].get("reason")

    def scenarios(self):
        self.wg_setup()
        for ns in ("team-a","team-b"):self.resource("Namespace",ns)
        for i in range(3):self.app("app"+str(i))
        self.gateway=wait_for(self.leader,"Connect quorum issuer")
        def remote_pod():
            code,pods=self.api(self.gateway,"GET","/api/v1/namespaces/team-a/pods")
            if code!=200:return None
            return next((p for p in pods["items"] if p["spec"]["nodeName"]!="q-n"+str(self.gateway["id"]) and any(c.get("ready") for c in p["status"]["containerStatuses"])),None)
        pod=wait_for(remote_pod,"Ready backend on a different daemon")
        owner=pod["metadata"]["labels"]["app"]
        self.backend_node=next(n for n in self.nodes if "q-n"+str(n["id"])==pod["spec"]["nodeName"])
        self.resource("Service","api",{"selector":{"app":owner},"ports":[{"port":80,"targetPort":9090},{"port":81,"targetPort":9090}]})
        self.app(owner,ns="team-b",marker="TEAM_B")
        self.resource("Service","api",{"selector":{"app":owner},"ports":[{"port":80,"targetPort":9090}]},ns="team-b")
        self.grant()
        self.resource("RoleBinding","viewer",roleRef={"kind":"ClusterRole","name":"view"},subjects=[{"kind":"Group","name":"viewers"}])
        self.ca=self.out/"gateway-ca.pem";docker("cp",self.gateway["name"]+":/root/.kube/royak-ca.pem",str(self.ca))
        self.check("issuer and only matching backend are distinct daemons",self.gateway!=self.backend_node,issuer=self.gateway["id"],backend=self.backend_node["id"])
        body=dict(service="api",port=80,ttl_seconds=60)
        self.check("anonymous session creation refused",request(self.gateway["api"]+self.cp(),"POST",body)[0]==401)
        self.check("ordinary viewer cannot create Connect access",self.call("POST",self.cp(),body,token=self.viewer)[0]==403)
        self.check("admin bearer is not an internal node identity",self.call("POST","/royak/v1/connect/node/open",{},token=self.token)[0]==401)
        self.check("namespace grant cannot reach same Service in another namespace",self.call("POST",self.cp("team-b"),body)[0]==403)
        self.check("port-specific grant refuses another declared port",self.call("POST",self.cp(),dict(body,port=81))[0]==403)
        self.check("arbitrary destination fields refused",self.call("POST",self.cp(),dict(body,host="127.0.0.1"))[0]==400)
        self.check("Connect permission does not grant pod port-forward",self.call("GET","/api/v1/namespaces/team-a/pods/"+pod["metadata"]["name"]+"/portforward")[0]==403)
        ident=self.session();s=self.stream(ident);self.echo(s,payload=bytes(range(256))*1024)
        self.check("256 KiB binary TCP spans frames to the namespace-correct remote Service over WireGuard",True)
        self.stream(ident,token=self.other,expected=403)
        self.check("stolen session id does not change authenticated owner",True)
        self.stream(ident,ns="team-b",expected=404)
        self.check("session id is bound to namespace",True)
        self.grant(ns="team-b")
        wait_for(lambda:any(p["metadata"]["labels"].get("app")==owner and any(c.get("ready") for c in p["status"]["containerStatuses"]) for p in self.pods("team-b")),"same-name backend Ready in team-b")
        other_id=self.session(ns="team-b");other_socket=self.stream(other_id,ns="team-b");self.echo(other_socket,b"TEAM_B")
        self.check("identical Service and workload names resolve to each namespace's actual backend",True)
        self.call("DELETE",self.cp("team-b")+"/"+other_id)
        counters={n["id"]:docker("exec",n["name"],"wg","show",self.iface,"transfer").strip() for n in self.nodes}
        handshakes={n["id"]:docker("exec",n["name"],"wg","show",self.iface,"latest-handshakes").strip() for n in self.nodes}
        self.check("WireGuard exchanged encrypted packets with a handshake",any(int(v.split()[-1])>0 for v in handshakes[self.gateway["id"]].splitlines()),transfer=counters,handshakes=handshakes)

        token_file=self.out/"client.token";token_file.write_text(self.user);token_file.chmod(0o600)
        common=["--server",self.gateway["api"],"--ca-cert",str(self.ca),"--token-file",str(token_file),"--namespace","team-a"]
        env=dict(os.environ,DOCKER_HOST="unix:///does-not-exist-connect",ROYAK_STATE="/does-not-exist-connect/state.json")
        process=subprocess.Popen([str(self.args.client),"connect","open",*common,"--service","api","--port","80","--ttl-seconds","45"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        self.children.append(process)
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            assert ready.select(15),"laptop client did not produce a bounded startup result"
        line=process.stdout.readline();assert line,line or process.stderr.read()
        opened=json.loads(line)
        with __import__("urllib.request",fromlist=["urlopen"]).urlopen("http://"+opened["local_address"],timeout=10) as result:answer=result.read()
        self.check("laptop CLI uses verified TLS without Docker or cluster-state access",answer==b"TEAM_A")
        self.check("laptop listener is loopback only",opened["local_address"].startswith("127.0.0.1:"))
        bad_common=common.copy();bad_common[1]="http://127.0.0.1:1"
        bad=subprocess.run([str(self.args.client),"connect","list",*bad_common],capture_output=True,text=True,timeout=5,env=env)
        self.check("CLI refuses plaintext server",bad.returncode==2 and "HTTPS" in bad.stderr)
        wrong_ca=self.out/"wrong-ca.pem";docker("cp",self.backend_node["name"]+":/root/.kube/royak-ca.pem",str(wrong_ca))
        bad_common=common.copy();bad_common[3]=str(wrong_ca)
        bad=subprocess.run([str(self.args.client),"connect","list",*bad_common],capture_output=True,text=True,timeout=10,env=env)
        self.check("CLI refuses an untrusted server certificate",bad.returncode==2 and "TLS verification failed" in bad.stderr)
        process.send_signal(__import__("signal").SIGINT);process.wait(timeout=8)
        self.check("Ctrl-C removes the local listener and revokes its session",self.call("GET",self.cp()+"/"+opened["session"])[1]["closed"])

        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        code,_=self.call("DELETE",self.cp()+"/"+ident)
        self.check("owner revoke closes already-open idle TCP socket",code==200 and self.closed(s) and self.reason(ident)=="revoked")
        self.stream(ident,expected=410);self.check("revoked session refuses new connections",True)
        started=time.monotonic();exp=self.session(5);s=self.stream(exp);self.echo(s)
        expired_closed=self.closed(s,8);elapsed=time.monotonic()-started
        meta=self.call("GET",self.cp()+"/"+exp)[1]
        self.check("TTL expiry closes already-open idle TCP socket, not prematurely",expired_closed and 4.75<=elapsed<=8 and meta["closed"] and meta["reason"]=="expired",elapsed_seconds=round(elapsed,3),metadata=meta)
        self.stream(exp,expected=410);self.check("expired session cannot reopen",True)
        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        leader=wait_for(self.leader,"leader before RBAC revoke")
        code,_=self.api(leader,"DELETE","/apis/rbac.authorization.k8s.io/v1/namespaces/team-a/rolebindings/connector")
        self.check("removing RoleBinding closes already-open TCP socket",code==200 and self.closed(s) and self.reason(ident)=="permission removed")
        self.check("removed permission refuses new sessions",self.call("POST",self.cp(),body)[0]==403)
        self.grant()
        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        self.resource("Role","connector",rules=[])
        self.check("editing a Role to remove access closes an already-open socket",self.closed(s) and self.reason(ident)=="permission removed")
        self.check("Role permission removal refuses new sessions",self.call("POST",self.cp(),body)[0]==403)
        self.grant()
        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        code,_=self.call("DELETE",self.cp()+"/"+ident,token=self.token)
        self.check("administrator revoke closes another owner's active socket",code==200 and self.closed(s) and self.reason(ident)=="revoked")
        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        docker("exec",self.backend_node["name"],"ip","link","set",self.iface,"down")
        try:
            self.check("WireGuard failure closes an existing remote stream",self.closed(s,6))
            self.stream(self.session(),expected=503)
            self.check("WireGuard failure has no ordinary-route fallback",True)
        finally:docker("exec",self.backend_node["name"],"ip","link","set",self.iface,"up")
        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        leader=wait_for(self.leader,"leader before Service change")
        code,_=self.api(leader,"DELETE","/api/v1/namespaces/team-a/services/api")
        self.check("Service deletion closes active socket",code==200 and self.closed(s) and self.reason(ident)=="Service changed or deleted")
        self.resource("Service","api",{"selector":{"app":owner},"ports":[{"port":80,"targetPort":9090}]})
        self.stream(ident,expected=410);self.check("same-name Service recreation does not resurrect old session",True)
        changed=self.session();changed_stream=self.stream(changed);self.echo(changed_stream);self.live(changed_stream)
        self.resource("Service","api",{"selector":{"app":owner},"ports":[{"port":80,"targetPort":9090},{"port":81,"targetPort":9090}]})
        self.check("committed Service configuration change closes an already-open stream",self.closed(changed_stream) and self.reason(changed)=="Service changed or deleted")
        self.app(owner,ready=False)
        # A safe rolling update deliberately keeps the old Ready pod serving.
        # Remove the owned old/candidate containers to inject actual backend
        # loss; replacements still use the committed false readiness probe.
        removed=0
        for node in self.nodes:
            ids=docker("exec",node["name"],"docker","ps","-q","--filter","label=royak.managed=true","--filter","label=royak.namespace=team-a","--filter","label=royak.deployment="+owner,"--filter","label=royak.role=main").split()
            if ids:docker("exec",node["name"],"docker","rm","-f",*ids);removed+=len(ids)
        self.check("actual owned backend loss injected during a NotReady rollout",removed>0)
        wait_for(lambda:not any(p["metadata"]["labels"].get("app")==owner and any(c.get("ready") for c in p["status"]["containerStatuses"]) for p in self.pods("team-a")),"target backend becomes unready")
        self.stream(self.session(),expected=503)
        self.check("unready team-a backend cannot fall through to Ready same-name team-b backend",True)
        self.app(owner)
        wait_for(lambda:any(p["metadata"]["labels"].get("app")==owner and any(c.get("ready") for c in p["status"]["containerStatuses"]) for p in self.pods("team-a")),"replacement backend Ready")
        ident=self.session(ttl=120)
        s=wait_for(lambda:self.stream(ident,allow_unavailable=True),"actual Ready replacement TCP backend",timeout=45)
        self.echo(s)
        self.check("new TCP connection reaches Ready replacement backend",True)
        audit_path="/lab/data/connect-audit.jsonl"
        docker("exec",self.gateway["name"],"chmod","0644",audit_path)
        code,data=self.call("POST",self.cp(),body)
        self.check("unsafe audit storage prevents new access",code==503)
        code,data=self.call("DELETE",self.cp()+"/"+ident)
        self.check("audit write failure cannot prevent revocation of active sockets",code==503 and data.get("revoked") and self.closed(s))
        docker("exec",self.gateway["name"],"chmod","0600",audit_path)
        audit=self.call("GET","/royak/v1/connect/namespaces/team-a/audit")[1]
        self.check("metadata audit records grants and closure without credentials",any(e["action"]=="created" for e in audit["items"]) and any(e["action"]=="closed" for e in audit["items"]) and all(t not in json.dumps(audit) for t in (self.user,self.other,self.token,self.cluster_secret)))
        for ns in ("team-a","team-b"):
            for session in self.call("GET",self.cp(ns))[1]["items"]:
                if not session["closed"]:self.call("DELETE",self.cp(ns)+"/"+session["id"])
        grants=[self.session() for _ in range(16)]
        self.check("per-user session bound rejects a seventeenth grant",self.call("POST",self.cp(),body)[0]==429)
        for grant in grants:self.call("DELETE",self.cp()+"/"+grant)
        # Capacity is a steady-state scenario, separate from the deliberately
        # disrupted deployment and its stale census entries during recovery.
        capacity_pod=next(p for p in self.pods("team-a") if p["spec"]["nodeName"]!="q-n"+str(self.gateway["id"]) and p["metadata"]["labels"]["app"]!=owner and any(c.get("ready") for c in p["status"]["containerStatuses"]))
        capacity_owner=capacity_pod["metadata"]["labels"]["app"]
        self.resource("Service","api",{"selector":{"app":capacity_owner},"ports":[{"port":80,"targetPort":9090}]})
        wait_for(lambda:self.service_converged(capacity_owner),"Service configuration observed on every node")
        self.check("concurrent stream capacity scenario targets another node",True,issuer=self.gateway["id"],backend=capacity_pod["spec"]["nodeName"])
        parallel_id=self.session(ttl=120)
        parallel=[self.stream(parallel_id) for _ in range(8)]
        for stream in parallel:self.echo(stream)
        self.stream(parallel_id,expected=429)
        for stream in parallel:self.live(stream)
        self.check("eight concurrent authorized streams stay live and a ninth is refused",self.call("GET",self.cp()+"/"+parallel_id)[1]["active_connections"]==8)
        self.call("DELETE",self.cp()+"/"+parallel_id)
        self.check("one revoke closes all eight existing streams",all(self.closed(stream) for stream in parallel))
        for _ in range(17):
            cycle=[self.session() for _ in range(16)]
            for grant in cycle:self.call("DELETE",self.cp()+"/"+grant)
        self.check("272 grant/revoke cycles cannot exhaust access through closed-session retention",True)
        ident=self.session();s=self.stream(ident);self.echo(s)
        follower=next(n for n in self.nodes if n!=self.gateway)
        code,_=request(follower["api"]+self.cp(),"POST",body,self.user)
        self.check("a non-authoritative follower cannot issue Connect sessions",code==421)
        self.live(s);installed=[]
        try:
            for peer in self.nodes:
                if peer==self.gateway:continue
                for chain,direction in (("INPUT","-s"),("OUTPUT","-d")):
                    rule=[chain,direction,peer["ip"],"-p","tcp","--dport","6443","-m","comment","--comment",self.run,"-j","DROP"]
                    docker("exec",self.gateway["name"],"iptables","-I",*rule);installed.append(rule)
            self.check("quorum loss closes active access even while WireGuard remains up",self.closed(s,5) and self.reason(ident)=="issuer lost authoritative state/quorum leadership")
            self.check("isolated former issuer refuses new access",self.call("POST",self.cp(),body)[0]==421)
            wait_for(lambda:self.leader(exclude=self.gateway),"majority elects during Connect partition",timeout=30)
        finally:
            for rule in reversed(installed):docker("exec",self.gateway["name"],"iptables","-D",*rule)
        self.check("expired quorum session stays closed after network healing",self.call("GET",self.cp()+"/"+ident)[1]["closed"])
        # Use a fresh session on the explicitly trusted current issuer for the
        # separate process-failure test; this is test setup, not client redirect.
        self.gateway=wait_for(self.leader,"confirmed issuer after healing")
        docker("cp",self.gateway["name"]+":/root/.kube/royak-ca.pem",str(self.ca))
        process_pod=next(p for p in self.pods("team-a") if p["spec"]["nodeName"]!="q-n"+str(self.gateway["id"]) and p["metadata"]["labels"]["app"]!=owner and any(c.get("ready") for c in p["status"]["containerStatuses"]))
        process_backend=next(n for n in self.nodes if "q-n"+str(n["id"])==process_pod["spec"]["nodeName"])
        self.resource("Service","api",{"selector":{"app":process_pod["metadata"]["labels"]["app"]},"ports":[{"port":80,"targetPort":9090}]})
        wait_for(lambda:self.service_converged(process_pod["metadata"]["labels"]["app"]),"process-failure Service configuration observed on every node")
        self.check("issuer process failure scenario has an actual remote backend",process_backend!=self.gateway,issuer=self.gateway["id"],backend=process_backend["id"])
        ident=self.session();s=self.stream(ident);self.echo(s);self.live(s)
        # SIGTERM requests graceful shutdown and may wait for an in-flight
        # reconcile operation. This scenario promises actual process failure,
        # not a guessed graceful-shutdown deadline.
        self.event("connect-faults.jsonl",kind="issuer_sigkill",node=self.gateway["id"])
        docker("exec",self.gateway["name"],"sh","-ec","kill -KILL $(cat /lab/royak.pid)")
        wait_for(lambda:self.api(self.gateway,"GET","/royak/v1/raft/status",timeout=1)[0]==0,"SIGKILLed issuer API is closed",timeout=3)
        self.check("issuer process death is observed before socket closure",True)
        self.check("issuer process failure closes an already-open remote stream",self.closed(s,6))
        wait_for(lambda:not docker("exec",process_backend["name"],"ss","-Hnt","state","established","(","dport","=",":9090",")").strip(),"remote handle lease releases backend TCP socket",timeout=6)
        self.check("origin failure releases remote backend sockets through the bounded lease",True)
        self.start_node(self.gateway)
        wait_for(lambda:self.api(self.gateway,"GET","/royak/v1/raft/status")[0]==200,"restarted issuer")
        self.check("restart never resurrects an old session",self.call("GET",self.cp()+"/"+ident)[0]==404)
        durable=docker("exec",self.gateway["name"],"sh","-ec","test $(stat -c %a /lab/data/connect-audit.jsonl) = 600; wc -l < /lab/data/connect-audit.jsonl").strip()
        durable_text=docker("exec",self.gateway["name"],"cat","/lab/data/connect-audit.jsonl")
        durable_events=[json.loads(line) for line in durable_text.splitlines()]
        self.check("private durable audit survives process restart with the exact granted session",int(durable)==len(durable_events) and any(event.get("session")==ident and event.get("action")=="created" for event in durable_events) and all(secret not in durable_text for secret in (self.user,self.other,self.viewer,self.token,self.cluster_secret,self.seal)),audit_records=len(durable_events))

    def execute_connect(self):
        print("Evidence: "+str(self.out),flush=True);failure=None
        fixture_sha=digest(Path(__file__));client_sha=digest(self.args.client)
        try:
            build=json.loads(self.binary.with_name(self.binary.name+".build.json").read_text())
            assert build["binary_sha256"]==digest(self.binary),"build manifest does not match binary"
            assert build["source_unchanged_during_build"] and build["source_sha256"]=={str(p.relative_to(ROOT)):digest(p) for p in source_inventory()},"build does not match current sources"
            (self.out/"build-manifest.json").write_text(json.dumps(build,indent=2))
            self.provision();self.scenarios()
            assert build["source_sha256"]=={str(p.relative_to(ROOT)):digest(p) for p in source_inventory()},"sources changed during Connect test"
            assert fixture_sha==digest(Path(__file__)) and client_sha==digest(self.args.client),"fixture/client changed during Connect test"
        except BaseException as error:
            failure=traceback.format_exc()
            for secret in (self.user,self.other,self.viewer,self.token,self.cluster_secret,self.seal):failure=failure.replace(secret,"[REDACTED]")
            print(failure,flush=True)
            if hasattr(self,"gateway"):
                try:
                    stacks=docker("exec",self.gateway["name"],"sh","-ec",'timeout 15 gdb -q -batch -ex "set auto-load safe-path /nonexistent" -ex "set print frame-arguments none" -ex "set print entry-values no" -ex "thread apply all bt 16" -p "$(cat /lab/royak.pid)"',timeout=20)
                    for secret in (self.user,self.other,self.viewer,self.token,self.cluster_secret,self.seal):stacks=stacks.replace(secret,"[REDACTED]")
                    (self.out/"issuer-stacks.txt").write_text(stacks)
                    print("Captured issuer thread stacks without frame arguments",flush=True)
                except Exception as diagnostic_error:print("Thread diagnostic unavailable: "+type(diagnostic_error).__name__,flush=True)
            self.diagnostics()
        finally:
            for s in self.sockets:s.close()
            for p in self.children:
                if p.poll() is None:p.terminate()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait()
                diagnostic=p.stderr.read()
                for secret in (self.user,self.other,self.viewer,self.token,self.cluster_secret,self.seal):diagnostic=diagnostic.replace(secret,"[REDACTED]")
                if diagnostic:(self.out/"client-stderr.log").write_text(diagnostic)
            self.cleanup()
            if (self.out/"cleanup.jsonl").exists():
                failure=failure or "owned resource cleanup failed; inspect cleanup.jsonl"
            for p in self.out.glob("node-*.log"):
                text=p.read_text();p.write_text(text.replace(self.user,"[REDACTED]").replace(self.other,"[REDACTED]").replace(self.viewer,"[REDACTED]"))
            if (self.out/"client.token").exists():(self.out/"client.token").unlink()
            (self.out/"connect-report.json").write_text(json.dumps(dict(passed=failure is None,failure=failure,checks=self.checks,binary_sha256=digest(self.binary),client_sha256=digest(self.args.client),fixture_sha256=digest(Path(__file__)),topology="single-host-three-daemon kernel WireGuard; no host VPN changes"),indent=2))
        return int(failure is not None)

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--binary",type=Path,required=True);parser.add_argument("--client",type=Path,required=True)
    args=parser.parse_args();args.client=args.client.resolve()
    for k,v in dict(seed=42,probe_mode="http",ui_check=False,rate=5,settle=20,duration=300,node_outage=45,baseline_availability=.99).items():setattr(args,k,v)
    raise SystemExit(ConnectLab(args).execute_connect())
