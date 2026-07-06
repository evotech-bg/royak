"""
Royak MCP Server — manage your cluster from Claude.

Deploy, scale, heal, monitor — all through natural language.
The brain detects. You decide. Claude executes.
"""

import json
import urllib.request
from fastmcp import FastMCP

API = "http://127.0.0.1:6443"

mcp = FastMCP("royak", instructions="""
You are connected to a Royak cluster — an AI-first container orchestrator.
Use these tools to deploy, manage, and monitor containers.
The cluster has a neural brain that detects anomalies and predicts load.
""")

def _get(path: str) -> dict:
    req = urllib.request.Request(f"{API}{path}")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())

def _post(path: str, data: str, content_type: str = "application/yaml") -> dict:
    req = urllib.request.Request(f"{API}{path}", data=data.encode(),
        headers={"Content-Type": content_type}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


@mcp.tool()
def nodes() -> str:
    """List all cluster nodes with status."""
    d = _get("/api/v1/nodes")
    lines = []
    for item in d.get("items", []):
        name = item["metadata"]["name"]
        status = item["status"]["conditions"][0]["reason"]
        lines.append(f"{name}: {status}")
    return f"{len(lines)} node(s)\n" + "\n".join(lines)


@mcp.tool()
def pods(namespace: str = "default") -> str:
    """List running pods, optionally filtered by namespace."""
    d = _get(f"/api/v1/namespaces/{namespace}/pods")
    lines = []
    for p in d.get("items", []):
        name = p["metadata"]["name"]
        phase = p["status"]["phase"]
        image = p["spec"]["containers"][0]["image"]
        lines.append(f"{name} ({image}): {phase}")
    return f"{len(lines)} pod(s)\n" + "\n".join(lines) if lines else "No pods running."


@mcp.tool()
def deployments(namespace: str = "default") -> str:
    """List all deployments with replica counts."""
    d = _get(f"/api/v1/namespaces/{namespace}/deployments")
    if not d.get("items"):
        d = _get("/apis/apps/v1/deployments")
    lines = []
    for dep in d.get("items", []):
        name = dep["metadata"]["name"]
        replicas = dep["spec"]["replicas"]
        lines.append(f"{name}: {replicas} replicas")
    return "\n".join(lines) if lines else "No deployments."


@mcp.tool()
def deploy(name: str, image: str, replicas: int = 1, namespace: str = "default") -> str:
    """Deploy a container to the cluster.

    Args:
        name: Deployment name (e.g. 'web', 'api', 'redis')
        image: Docker image (e.g. 'nginx:alpine', 'redis:7')
        replicas: Number of replicas (default 1)
        namespace: Kubernetes namespace (default 'default')
    """
    yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {namespace}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {name}
  template:
    spec:
      containers:
      - name: {name}
        image: {image}"""
    result = _post("/apis/apps/v1/deployments", yaml)
    return result.get("message", str(result))


@mcp.tool()
def scale(deployment: str, replicas: int) -> str:
    """Scale a deployment to the desired number of replicas.

    Args:
        deployment: Name of the deployment to scale
        replicas: Target number of replicas
    """
    patch = json.dumps({"spec": {"replicas": replicas}})
    req = urllib.request.Request(
        f"{API}/apis/apps/v1/namespaces/default/deployments/{deployment}",
        data=patch.encode(),
        headers={"Content-Type": "application/json"},
        method="PATCH"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
            return d.get("message", f"Scaled {deployment} to {replicas} replicas")
    except Exception as e:
        return f"Scale failed: {e}"


@mcp.tool()
def delete(resource_type: str, name: str) -> str:
    """Delete a resource from the cluster.

    Args:
        resource_type: Type of resource ('deployment', 'configmap', 'namespace')
        name: Name of the resource to delete
    """
    path_map = {
        "deployment": f"/apis/apps/v1/deployments/{name}",
        "configmap": f"/api/v1/configmaps/{name}",
        "secret": f"/api/v1/secrets/{name}",
        "namespace": f"/api/v1/namespaces/{name}",
    }
    path = path_map.get(resource_type, f"/api/v1/{resource_type}s/{name}")
    req = urllib.request.Request(f"{API}{path}", method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
            return d.get("message", str(d))
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def health() -> str:
    """Check cluster health: API server, brain, node status."""
    lines = []
    try:
        req = urllib.request.Request(f"{API}/healthz")
        with urllib.request.urlopen(req, timeout=3) as r:
            lines.append(f"API: {r.read().decode()}")
    except Exception as e:
        lines.append(f"API: DOWN ({e})")

    try:
        d = _get("/royak/v1/brain")
        lines.append(f"Brain: {d.get('status', '?')} — features: {', '.join(d.get('features', []))}")
    except:
        lines.append("Brain: unavailable")

    try:
        d = _get("/api/v1/nodes")
        for item in d.get("items", []):
            name = item["metadata"]["name"]
            status = item["status"]["conditions"][0]["reason"]
            lines.append(f"Node {name}: {status}")
    except:
        lines.append("Nodes: unavailable")

    return "\n".join(lines)


@mcp.tool()
def heal(pod_name: str) -> str:
    """Attempt to heal a broken pod by deleting it (the deployment will recreate it).

    Args:
        pod_name: Name of the broken pod to restart
    """
    # In Royak, healing = delete the pod, reconcile loop recreates it
    req = urllib.request.Request(f"{API}/api/v1/pods/{pod_name}", method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return f"Pod {pod_name} deleted — reconcile loop will recreate it"
    except Exception as e:
        return f"Heal failed: {e} — the brain may handle this automatically via ANOMALY detection"


@mcp.tool()
def describe(resource_type: str, name: str) -> str:
    """Get detailed information about a resource — events, status, spec.

    Args:
        resource_type: Type of resource ('deployment', 'pod', 'node')
        name: Name of the resource
    """
    try:
        d = _get(f"/royak/v1/describe/{resource_type}/{name}")
        lines = [f"=== {d.get('resource', resource_type)}/{name} ==="]
        if "metadata" in d:
            lines.append(f"Namespace: {d['metadata'].get('namespace', 'n/a')}")
        if "spec" in d:
            for k, v in d["spec"].items():
                if isinstance(v, list):
                    lines.append(f"{k}:")
                    for item in v:
                        lines.append(f"  {item}")
                else:
                    lines.append(f"{k}: {v}")
        if d.get("events"):
            lines.append("\nEvents:")
            for e in d["events"]:
                lines.append(f"  {e}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def exec_command(pod_name: str, command: str = "sh") -> str:
    """Execute a command inside a running pod.

    Args:
        pod_name: Name of the pod
        command: Command to run (default 'sh')
    """
    try:
        d = _post(f"/api/v1/namespaces/default/pods/{pod_name}/exec?command={command}", "",
                   content_type="application/json")
        output = d.get("output", "")
        code = d.get("exitCode", -1)
        return f"exit {code}\n{output}"
    except Exception as e:
        return f"Exec failed: {e}"


@mcp.tool()
def rollout_status(deployment: str) -> str:
    """Check the rollout status of a deployment — progress, old/new images.

    Args:
        deployment: Name of the deployment
    """
    try:
        d = _get(f"/royak/v1/rollout/{deployment}")
        status = d.get("status", "unknown")
        if status == "complete" and "message" in d:
            return f"{deployment}: {d['message']}"
        return (f"{deployment}: {status}\n"
                f"  {d.get('oldImage', '?')} → {d.get('newImage', '?')}\n"
                f"  Progress: {d.get('progress', '?')}")
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def top(resource: str = "pods") -> str:
    """Show resource usage (CPU/memory) for pods or nodes.

    Args:
        resource: 'pods' or 'nodes' (default 'pods')
    """
    try:
        d = _get(f"/royak/v1/top/{resource}")
        lines = []
        for item in d.get("items", []):
            name = item["name"]
            cpu = item.get("cpu", "n/a")
            mem = item.get("memory", "n/a")
            extra = f"  pods: {item['pods']}" if "pods" in item else ""
            lines.append(f"{name}  CPU: {cpu}  MEM: {mem}{extra}")
        return "\n".join(lines) if lines else f"No {resource} found."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def apply_patch(deployment: str, replicas: int = None, image: str = None) -> str:
    """Patch a deployment — change replicas or image (triggers rolling update).

    Args:
        deployment: Name of the deployment to patch
        replicas: New replica count (optional)
        image: New container image (optional, triggers rolling update)
    """
    patch = {"spec": {}}
    if replicas is not None:
        patch["spec"]["replicas"] = replicas
    if image is not None:
        patch["spec"]["template"] = {"spec": {"containers": [{"image": image}]}}
    body = json.dumps(patch)
    req = urllib.request.Request(
        f"{API}/apis/apps/v1/namespaces/default/deployments/{deployment}",
        data=body.encode(),
        headers={"Content-Type": "application/json"},
        method="PATCH"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
            return d.get("message", str(d))
    except Exception as e:
        return f"Patch failed: {e}"


if __name__ == "__main__":
    mcp.run()
