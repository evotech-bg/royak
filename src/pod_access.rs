//! Runtime authority is taken from an immutable, server-created Docker label,
//! never from the latest desired template or a user's Pod metadata labels.
//! Namespace permissions alone do not grant access to a host-capable Pod.
use crate::{auth, docker, reconcile::DesiredWorld, storage_identity::Uid, store};
use serde::{Deserialize, Serialize};

pub const LABEL_CONTRACT: &str = "royak.runtime-access";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContract {
    version: u32,
    namespace_uid: Uid,
    host_access: bool,
}

pub fn launch_label(plan: &crate::workload::PodLaunch) -> Result<String, String> {
    let namespace_uid = plan
        .namespace_uid
        .clone()
        .ok_or("runtime access requires a namespace incarnation")?;
    let host_access = plan
        .init_containers
        .iter()
        .chain(&plan.containers)
        .any(|c| c.host_access.is_some() || crate::host_access::launch_requires(c));
    serde_json::to_string(&RuntimeContract {
        version: 1,
        namespace_uid,
        host_access,
    })
    .map_err(|e| e.to_string())
}

fn contract(c: &docker::DockerContainer) -> Result<RuntimeContract, String> {
    let raw = c
        .labels
        .get(LABEL_CONTRACT)
        .ok_or("legacy container has no runtime-access contract; operator migration required")?;
    if raw.len() > 1024 {
        return Err("invalid runtime-access contract".into());
    }
    let binding: RuntimeContract =
        serde_json::from_str(raw).map_err(|_| "invalid runtime-access contract")?;
    if binding.version != 1 {
        return Err("unsupported runtime-access contract".into());
    }
    Ok(binding)
}

pub fn validate_runtime(
    world: &DesiredWorld,
    c: &docker::DockerContainer,
) -> Result<RuntimeContract, String> {
    let binding = contract(c)?;
    let ns = c
        .labels
        .get(store::LABEL_NAMESPACE)
        .ok_or("runtime namespace missing")?;
    if !store::container_is_ours(c, &world.cluster_id, Some(&store::node_name())) {
        return Err("container is not owned by this cluster and node".into());
    }
    if world.storage_identities.namespaces.get(ns) != Some(&binding.namespace_uid) {
        return Err("container belongs to an obsolete namespace incarnation".into());
    }
    Ok(binding)
}

/// Local retirement does not delete a volume, adopt an old container, or mint
/// a permit. A node behind a newer placement must first catch up its state.
pub fn retirement_reason(world: &DesiredWorld, c: &docker::DockerContainer) -> Option<String> {
    if !store::container_is_ours(c, &world.cluster_id, Some(&store::node_name())) {
        return None;
    }
    if !c.labels.contains_key(store::LABEL_POD) {
        return None;
    }
    if c.labels
        .get(crate::workload::LABEL_GENERATION)
        .and_then(|g| g.parse::<u64>().ok())
        .is_some_and(|g| g > world.generation)
    {
        return None;
    }
    validate_runtime(world, c).err()
}

#[derive(Clone)]
pub struct Permit {
    identity: auth::Identity,
    attrs: auth::Attrs,
    namespace_uid: Uid,
    host_access: bool,
    pub container_id: String,
}

impl Permit {
    pub fn issue(
        world: &DesiredWorld,
        caller: &auth::Identity,
        attrs: &auth::Attrs,
        c: &docker::DockerContainer,
    ) -> Result<Self, (u16, String)> {
        if !auth::authorize(world, caller, attrs) {
            return Err((403, "Pod access permission denied".into()));
        }
        let binding = validate_runtime(world, c).map_err(|e| (409, e))?;
        if attrs.namespace.as_deref() != c.labels.get(store::LABEL_NAMESPACE).map(String::as_str)
            || attrs.name.as_ref() != c.labels.get(store::LABEL_POD)
        {
            return Err((
                409,
                "Pod access target does not match the runtime container".into(),
            ));
        }
        if binding.host_access && !crate::host_access::allowed(world, caller) {
            return Err((
                403,
                "access to a host-capable Pod requires cluster-scoped use hostaccess permission"
                    .into(),
            ));
        }
        Ok(Self {
            identity: caller.clone(),
            attrs: attrs.clone(),
            namespace_uid: binding.namespace_uid,
            host_access: binding.host_access,
            container_id: c.id.clone(),
        })
    }
    pub fn valid(&self, world: &DesiredWorld) -> bool {
        self.attrs
            .namespace
            .as_ref()
            .and_then(|ns| world.storage_identities.namespaces.get(ns))
            == Some(&self.namespace_uid)
            && auth::authorize(world, &self.identity, &self.attrs)
            && (!self.host_access || crate::host_access::allowed(world, &self.identity))
    }
    pub fn valid_runtime(&self,world:&DesiredWorld,c:&docker::DockerContainer)->bool{
        c.id==self.container_id&&c.state=="running"&&self.valid(world)
            &&self.attrs.namespace.as_deref()==c.labels.get(store::LABEL_NAMESPACE).map(String::as_str)
            &&self.attrs.name.as_ref()==c.labels.get(store::LABEL_POD)
            &&validate_runtime(world,c).is_ok_and(|binding|binding.namespace_uid==self.namespace_uid&&binding.host_access==self.host_access)
    }
}

/// Only accepted on the signed+sealed node endpoint. The receiving node checks
/// current RBAC and its ACTUAL container, not the sender's cached PodView.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRequest {
    pub namespace: String,
    pub namespace_uid: Uid,
    pub pod: String,
    pub container: Option<String>,
    pub tail: u32,
    pub user: String,
    pub groups: Vec<String>,
}
impl LogRequest {
    pub fn identity(&self) -> auth::Identity {
        auth::Identity {
            user: self.user.clone(),
            groups: self.groups.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(
        host: bool,
    ) -> (
        DesiredWorld,
        docker::DockerContainer,
        auth::Identity,
        auth::Attrs,
    ) {
        let mut world = DesiredWorld::new();
        for r in crate::spec::parse_yaml("kind: Deployment\nmetadata: {name: web, namespace: lab}\nspec:\n  template:\n    spec:\n      containers: [{name: main, image: 'busybox:1.36'}]\n").unwrap() { world.apply(&r).unwrap(); }
        let ns = world.storage_identities.namespaces["lab"].clone();
        let mut labels = std::collections::HashMap::from([
            (store::LABEL_MANAGED.into(), "true".into()),
            (store::LABEL_CLUSTER.into(), world.cluster_id.clone()),
            (store::LABEL_NODE.into(), store::node_name()),
            (store::LABEL_NAMESPACE.into(), "lab".into()),
            (store::LABEL_POD.into(), "rk-lab_web-1".into()),
        ]);
        labels.insert(
            LABEL_CONTRACT.into(),
            serde_json::to_string(&RuntimeContract {
                version: 1,
                namespace_uid: ns,
                host_access: host,
            })
            .unwrap(),
        );
        world.rbac_roles.insert(
            "reader".into(),
            crate::reconcile::RbacRole {
                name: "reader".into(),
                rules: vec![crate::reconcile::RbacRule {
                    verbs: vec!["get".into()],
                    resources: vec!["pods/log".into()],
                    namespaces: vec!["lab".into()],
                    resource_names: vec![],
                }],
                namespace: None,
                kind: "ClusterRole".into(),
            },
        );
        world.rbac_bindings.insert(
            "reader".into(),
            crate::reconcile::RbacBinding {
                name: "reader".into(),
                namespace: None,
                role_kind: "ClusterRole".into(),
                role_name: "reader".into(),
                subjects: vec![crate::reconcile::RbacSubject {
                    kind: "User".into(),
                    name: "alice".into(),
                    namespace: None,
                }],
            },
        );
        let c = docker::DockerContainer {
            id: "a".repeat(64),
            names: vec!["/rk-lab_web-1".into()],
            image: "busybox:1.36".into(),
            state: "running".into(),
            status: "Up".into(),
            labels,
            ports: vec![],
        };
        (
            world,
            c,
            auth::Identity {
                user: "alice".into(),
                groups: vec![],
            },
            auth::Attrs::new(
                "get",
                "pods",
                Some("log"),
                Some("lab"),
                Some("rk-lab_web-1"),
            ),
        )
    }
    #[test]
    fn actual_runtime_not_latest_desired_controls_host_access() {
        let (world, c, id, attrs) = fixture(true);
        assert_eq!(Permit::issue(&world, &id, &attrs, &c).err().unwrap().0, 403);
        let master = auth::Identity {
            user: "admin".into(),
            groups: vec![auth::MASTERS_GROUP.into()],
        };
        assert!(Permit::issue(&world, &master, &attrs, &c).is_ok());
    }
    #[test]
    fn ordinary_stream_is_bound_to_rbac_and_namespace_incarnation() {
        let (mut world, c, id, attrs) = fixture(false);
        let p = Permit::issue(&world, &id, &attrs, &c).unwrap();
        assert!(p.valid(&world));
        world.rbac_bindings.remove("reader");
        assert!(!p.valid(&world));
        let (mut world, c, id, attrs) = fixture(false);
        let p = Permit::issue(&world, &id, &attrs, &c).unwrap();
        world.storage_identities.namespaces.remove("lab");
        assert!(!p.valid(&world));
    }
    #[test]
    fn removing_host_permission_revokes_an_existing_host_session() {
        let (mut world, c, id, attrs) = fixture(true);
        for r in crate::spec::parse_yaml("kind: ClusterRole\nmetadata: {name: host-reader}\nrules: [{resources: [hostaccess], verbs: [use]}]\n---\nkind: ClusterRoleBinding\nmetadata: {name: host-reader}\nroleRef: {kind: ClusterRole, name: host-reader}\nsubjects: [{kind: User, name: alice}]\n").unwrap(){world.apply(&r).unwrap();}
        let permit = Permit::issue(&world, &id, &attrs, &c).unwrap();
        assert!(permit.valid(&world));
        world.rbac_bindings.remove("host-reader");
        assert!(!permit.valid(&world));
        assert_eq!(Permit::issue(&world, &id, &attrs, &c).err().unwrap().0, 403);
    }
    #[test]
    fn legacy_malformed_wrong_namespace_and_foreign_runtime_fail_closed() {
        let (world, mut c, id, attrs) = fixture(false);
        c.labels.remove(LABEL_CONTRACT);
        assert_eq!(Permit::issue(&world, &id, &attrs, &c).err().unwrap().0, 409);
        assert!(retirement_reason(&world, &c).is_some());
        c.labels.insert(
            crate::workload::LABEL_GENERATION.into(),
            (world.generation + 1).to_string(),
        );
        assert!(retirement_reason(&world, &c).is_none());
        for raw in ["{}", "not-json", &"x".repeat(1025)] {
            c.labels.insert(LABEL_CONTRACT.into(), raw.into());
            assert!(validate_runtime(&world, &c).is_err());
        }
        let (world, mut c, _, _) = fixture(false);
        c.labels
            .insert(store::LABEL_CLUSTER.into(), "foreign".into());
        assert!(validate_runtime(&world, &c).is_err());
        assert!(retirement_reason(&world, &c).is_none());
    }
}
