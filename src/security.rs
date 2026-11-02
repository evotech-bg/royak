//! Supported security-context subset. Unknown settings fail closed.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
static DOCKER_RUNTIME: AtomicBool = AtomicBool::new(true);
pub fn set_docker_runtime(enabled: bool) { DOCKER_RUNTIME.store(enabled, Ordering::SeqCst); }
pub fn runtime_supported() -> bool { DOCKER_RUNTIME.load(Ordering::SeqCst) }
pub fn world_has_constraints(w: &crate::reconcile::DesiredWorld) -> bool {
    w.deployments.values().any(|d| d.containers.iter().chain(d.init_containers.iter()).any(|c| c.security_context.is_some()))
        || w.daemonsets.values().any(|d| d.container.security_context.is_some())
        || w.jobs.values().any(|d| d.container.security_context.is_some())
        || w.cronjobs.values().any(|d| d.container.security_context.is_some())
}
pub fn state_has_constraints(s: &crate::store::DesiredState) -> bool {
    s.deployments.values().any(|d| d.containers.iter().chain(d.init_containers.iter()).any(|c| c.security_context.is_some()))
        || s.daemonsets.values().any(|d| d.container.security_context.is_some())
        || s.jobs.values().any(|d| d.container.security_context.is_some())
        || s.cronjobs.values().any(|d| d.container.security_context.is_some())
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PodSecurityContext {
    pub run_as_user: Option<u32>,
    pub run_as_group: Option<u32>,
    pub run_as_non_root: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)] pub add: Vec<String>,
    #[serde(default)] pub drop: Vec<String>,
}

fn capability(value: &str) -> Result<String, String> {
    let name = value.strip_prefix("CAP_").unwrap_or(value);
    const KNOWN: &str = "ALL CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE";
    if KNOWN.split_whitespace().any(|n| n == name) { Ok(name.to_string()) }
    else { Err(format!("securityContext: unsupported Linux capability {value:?}")) }
}

impl SecurityContext {
    pub fn effective(pod: Option<&PodSecurityContext>, container: Option<&Self>) -> Result<Option<Self>, String> {
        if pod.is_none() && container.is_none() { return Ok(None); }
        if !runtime_supported() { return Err("securityContext is unsupported by experimental NeuroPod; use Docker runtime".into()); }
        let mut out = container.cloned().unwrap_or_default();
        if let Some(pod) = pod {
            out.run_as_user = out.run_as_user.or(pod.run_as_user);
            out.run_as_group = out.run_as_group.or(pod.run_as_group);
            out.run_as_non_root = out.run_as_non_root.or(pod.run_as_non_root);
        }
        out.validate()?;
        Ok(Some(out))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.run_as_user == Some(u32::MAX) || self.run_as_group == Some(u32::MAX) {
            return Err("securityContext: UID/GID 4294967295 is reserved".into());
        }
        if self.privileged == Some(true) { return Err("securityContext: privileged containers are unsupported".into()); }
        if self.run_as_non_root == Some(true) && self.run_as_user == Some(0) {
            return Err("securityContext: runAsNonRoot conflicts with runAsUser 0".into());
        }
        if let Some(caps) = &self.capabilities {
            for cap in caps.add.iter().chain(caps.drop.iter()) { capability(cap)?; }
            if self.allow_privilege_escalation == Some(false) && caps.add.iter().any(|c| {
                matches!(capability(c).as_deref(), Ok("SYS_ADMIN" | "ALL"))
            }) { return Err("securityContext: no privilege escalation conflicts with SYS_ADMIN/ALL".into()); }
        }
        Ok(())
    }

    pub fn needs_image_user(&self) -> bool {
        self.run_as_user.is_none() && (self.run_as_non_root == Some(true) || self.run_as_group.is_some())
    }

    /// Runtime checks use this node's actual image metadata. Named/unknown image
    /// users cannot prove non-root; explicit numeric runAsUser resolves that.
    pub fn docker_options(&self, image_user: &str) -> Result<(Option<String>, serde_json::Map<String, serde_json::Value>), String> {
        self.validate()?;
        let uid = self.run_as_user.map(|n| n.to_string()).unwrap_or_else(|| image_user.split(':').next().unwrap_or("").to_string());
        let numeric_uid = uid.parse::<u32>().ok().filter(|n| *n > 0 && *n < u32::MAX);
        if self.run_as_non_root == Some(true) && numeric_uid.is_none() {
            return Err("securityContext: cannot prove non-root image user; specify numeric nonzero runAsUser".into());
        }
        let user = if let Some(group) = self.run_as_group {
            let selected = if self.run_as_non_root == Some(true) {
                numeric_uid.unwrap().to_string()
            } else if uid.is_empty() { "0".into() } else { uid.clone() };
            Some(format!("{selected}:{group}"))
        } else if self.run_as_non_root == Some(true) && self.run_as_user.is_none() {
            // Pin the inspected numeric user on create too: a mutable image tag
            // changing between inspect/create must never turn this into root.
            let suffix = image_user.split_once(':').map(|(_, group)| format!(":{group}")).unwrap_or_default();
            Some(format!("{}{suffix}", numeric_uid.unwrap()))
        } else { self.run_as_user.map(|n| n.to_string()) };
        let mut host = serde_json::Map::new();
        if let Some(ro) = self.read_only_root_filesystem { host.insert("ReadonlyRootfs".into(), ro.into()); }
        if self.allow_privilege_escalation == Some(false) { host.insert("SecurityOpt".into(), serde_json::json!(["no-new-privileges:true"])); }
        if let Some(value) = self.privileged { host.insert("Privileged".into(), value.into()); }
        if let Some(caps) = &self.capabilities {
            host.insert("CapAdd".into(), serde_json::json!(caps.add.iter().map(|c| capability(c).unwrap()).collect::<Vec<_>>()));
            host.insert("CapDrop".into(), serde_json::json!(caps.drop.iter().map(|c| capability(c).unwrap()).collect::<Vec<_>>()));
        }
        Ok((user, host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inheritance_and_docker_enforcement() {
        let pod = PodSecurityContext { run_as_user: Some(1000), run_as_group: Some(2000), run_as_non_root: Some(true) };
        let c: SecurityContext = serde_json::from_value(serde_json::json!({"runAsUser":10001,"readOnlyRootFilesystem":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}})).unwrap();
        let (user, host) = SecurityContext::effective(Some(&pod), Some(&c)).unwrap().unwrap().docker_options("").unwrap();
        assert_eq!(user.as_deref(), Some("10001:2000"));
        assert_eq!(host["ReadonlyRootfs"], true);
        assert_eq!(host["CapDrop"], serde_json::json!(["ALL"]));
        assert_eq!(host["SecurityOpt"], serde_json::json!(["no-new-privileges:true"]));
    }
    #[test]
    fn nonroot_and_unknown_fields_fail_closed() {
        let c = SecurityContext { run_as_non_root: Some(true), ..Default::default() };
        for user in ["", "0", "0:1000", "app"] { assert!(c.docker_options(user).is_err()); }
        assert!(c.docker_options("1000:1000").is_ok());
        assert_eq!(c.docker_options("+1000").unwrap().0.as_deref(), Some("1000"));
        let grouped = SecurityContext { run_as_group: Some(42), ..c.clone() };
        assert_eq!(grouped.docker_options("+1000").unwrap().0.as_deref(), Some("1000:42"));
        assert!(c.docker_options("4294967295").is_err());
        assert!(serde_json::from_value::<SecurityContext>(serde_json::json!({"seccompProfile":{"type":"RuntimeDefault"}})).is_err());
        assert!(serde_json::from_value::<PodSecurityContext>(serde_json::json!({"fsGroup":1000})).is_err());
    }
    #[test]
    fn contradictory_privileges_are_rejected() {
        assert!(SecurityContext { privileged: Some(true), ..Default::default() }.validate().is_err());
        assert!(SecurityContext { run_as_user: Some(0), run_as_non_root: Some(true), ..Default::default() }.validate().is_err());
        let c = SecurityContext { capabilities: Some(Capabilities { add: vec!["SYS_ADMIN".into()], drop: vec![] }), allow_privilege_escalation: Some(false), ..Default::default() };
        assert!(c.validate().is_err());
    }
}
