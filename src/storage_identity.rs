//! Server-owned storage identities. Names are indexes, never data authority.
//!
//! A schema-4 identity is persisted/replicated before it may authorize a backend
//! operation. This module does not itself grant attachment or adopt legacy data.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::reconcile::{StoredPV, StoredPVC};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Uid(String);

impl<'de> Deserialize<'de> for Uid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 32 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(serde::de::Error::custom("storage UID must be 32 lowercase hex characters"));
        }
        Ok(Self(s))
    }
}

impl Uid {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8;16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    pub fn as_str(&self) -> &str { &self.0 }
    fn migrated(cluster: &str, kind: &str, key: &str) -> Self {
        let mut h = Sha256::new();
        // Length delimiting avoids ambiguous concatenation. Deterministic old
        // state migration is identical on every Raft peer; new objects use RNG.
        for value in ["royak-storage-schema4-migration", cluster, kind, key] {
            h.update((value.len() as u64).to_be_bytes()); h.update(value.as_bytes());
        }
        Self(h.finalize()[..16].iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimIdentity {
    pub uid: Uid,
    pub namespace_uid: Uid,
}

/// Version zero is only a deserialization marker for pre-schema-4 state. No
/// backend may accept it. Missing identity state in a schema-4 file is an error.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Identities {
    pub version: u32,
    pub namespaces: BTreeMap<String, Uid>,
    pub claims: BTreeMap<String, ClaimIdentity>,
    pub volumes: BTreeMap<String, Uid>,
    pub lifecycle: crate::storage_lifecycle::Registry,
}

impl Identities {
    pub fn fresh() -> Self {
        let mut value = Self { version: 1, ..Self::default() };
        value.namespaces.insert(crate::store::DEFAULT_NS.into(), Uid::new());
        value
    }

    pub fn synchronize(&mut self, namespaces: &[String], pvs: &HashMap<String,StoredPV>, pvcs: &HashMap<String,StoredPVC>) -> Result<(),String> {
        if self.version != 1 { return Err("storage identities are not migrated".into()); }
        self.namespaces.retain(|name,_| namespaces.contains(name));
        for name in namespaces { self.namespaces.entry(name.clone()).or_insert_with(Uid::new); }
        self.claims.retain(|key,_| pvcs.contains_key(key));
        self.volumes.retain(|key,_| pvs.contains_key(key));
        for name in pvs.keys() { self.volumes.entry(name.clone()).or_insert_with(Uid::new); }
        for (key,claim) in pvcs {
            let ns = self.namespaces.get(&claim.namespace).ok_or("claim has no namespace identity")?;
            if let Some(existing) = self.claims.get(key) {
                if &existing.namespace_uid != ns { return Err("claim belongs to a previous namespace incarnation".into()); }
            } else {
                self.claims.insert(key.clone(), ClaimIdentity { uid: Uid::new(), namespace_uid: ns.clone() });
            }
        }
        Ok(())
    }

    pub fn migrate(state: &mut crate::store::DesiredState) -> Result<(),String> {
        if !state.storage_identities.lifecycle.is_empty() {
            return Err("legacy state/envelope cannot import managed volume authority".into());
        }
        if state.storage_identities.version == 0 {
            if !state.namespaces.iter().any(|n| n == crate::store::DEFAULT_NS) {
                state.namespaces.push(crate::store::DEFAULT_NS.into());
            }
            let mut ids = Self { version: 1, ..Self::default() };
            for ns in &state.namespaces { ids.namespaces.insert(ns.clone(), Uid::migrated(&state.cluster_id,"Namespace",ns)); }
            for (key,claim) in &state.pvcs {
                let ns = ids.namespaces.get(&claim.namespace).ok_or("legacy claim has no namespace")?;
                ids.claims.insert(key.clone(), ClaimIdentity { uid: Uid::migrated(&state.cluster_id,"PVC",key), namespace_uid: ns.clone() });
            }
            for name in state.pvs.keys() { ids.volumes.insert(name.clone(), Uid::migrated(&state.cluster_id,"PV",name)); }
            state.storage_identities = ids;
        }
        state.storage_identities.validate(state)
    }

    pub fn validate(&self, state: &crate::store::DesiredState) -> Result<(),String> {
        if self.version != 1 { return Err("unsupported or missing storage identity version".into()); }
        let ns: BTreeSet<_> = state.namespaces.iter().cloned().collect();
        if ns.len()!=state.namespaces.len() || ns!=self.namespaces.keys().cloned().collect()
            || !ns.contains(crate::store::DEFAULT_NS) {
            return Err("namespace identities do not match authoritative namespaces".into());
        }
        if self.claims.keys().ne(state.pvcs.keys()) || self.volumes.keys().ne(state.pvs.keys()) {
            return Err("storage identities do not match authoritative claims/volumes".into());
        }
        for (key,c) in &state.pvcs {
            if key != &crate::store::obj_key(&c.namespace,&c.name)
                || self.namespaces.get(&c.namespace) != Some(&self.claims[key].namespace_uid) {
                return Err("claim namespace identity mismatch".into());
            }
        }
        let mut unique = HashSet::new();
        for id in self.namespaces.values().chain(self.volumes.values()).chain(self.claims.values().map(|c| &c.uid)) {
            if !unique.insert(id) { return Err("duplicate server-owned storage UID".into()); }
        }
        self.lifecycle.validate(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::DesiredWorld;
    fn apply(w: &mut DesiredWorld, kind: &str, ns: &str, name: &str) {
        let r = serde_json::from_value(serde_json::json!({"kind":kind,"metadata":{"name":name,"namespace":ns},"spec":{}})).unwrap();
        w.apply(&r).unwrap();
    }

    #[test]
    fn namespace_reapply_and_restart_preserve_uid_but_recreation_rotates_it() {
        let mut w=DesiredWorld::new();apply(&mut w,"Namespace","","team");
        let first=w.storage_identities.namespaces["team"].clone();
        apply(&mut w,"Namespace","","team");assert_eq!(w.storage_identities.namespaces["team"],first);
        let mut back=DesiredWorld::from_state(w.to_state());assert_eq!(back.storage_identities.namespaces["team"],first);
        back.delete_resource("namespace","","team").unwrap();apply(&mut back,"Namespace","","team");
        assert_ne!(back.storage_identities.namespaces["team"],first);
    }

    #[test]
    fn claim_and_volume_recreation_do_not_reuse_identity() {
        let mut w=DesiredWorld::new();apply(&mut w,"PersistentVolume","","disk");apply(&mut w,"PersistentVolumeClaim","a","data");
        let pv=w.storage_identities.volumes["disk"].clone();let claim=w.storage_identities.claims["a/data"].clone();
        apply(&mut w,"PersistentVolumeClaim","a","data");assert_eq!(w.storage_identities.claims["a/data"],claim);
        w.delete_resource("pvc","a","data").unwrap();apply(&mut w,"PersistentVolumeClaim","a","data");
        assert_ne!(w.storage_identities.claims["a/data"].uid,claim.uid);
        w.delete_resource("pvc","a","data").unwrap();w.delete_resource("pv","","disk").unwrap();apply(&mut w,"PersistentVolume","","disk");
        assert_ne!(w.storage_identities.volumes["disk"],pv);
    }

    #[test]
    fn migration_is_deterministic_and_does_not_adopt_backend_authority() {
        let mut a=DesiredWorld::new().to_state();a.storage_identities=Identities::default();
        let mut b=a.clone();Identities::migrate(&mut a).unwrap();Identities::migrate(&mut b).unwrap();
        assert_eq!(a.storage_identities,b.storage_identities);
        let before=a.storage_identities.clone();Identities::migrate(&mut a).unwrap();assert_eq!(before,a.storage_identities);
        assert!(a.storage_identities.claims.is_empty());assert!(a.storage_identities.volumes.is_empty());
    }

    #[test]
    fn invalid_or_reused_uid_and_namespace_mismatch_are_rejected() {
        assert!(serde_json::from_str::<Uid>("\"admin-chosen\"").is_err());
        let mut w=DesiredWorld::new();apply(&mut w,"PersistentVolumeClaim","a","data");
        let mut s=w.to_state();s.storage_identities.claims.get_mut("a/data").unwrap().namespace_uid=Uid::new();
        assert!(s.storage_identities.validate(&s).is_err());
        let mut s=w.to_state();let duplicate=s.storage_identities.namespaces["a"].clone();
        s.storage_identities.claims.get_mut("a/data").unwrap().uid=duplicate;
        assert!(s.storage_identities.validate(&s).is_err());
    }
}
