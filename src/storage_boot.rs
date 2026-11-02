//! Boot incarnation is an identity, not a liveness/fencing certificate.
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct BootId(String);

impl<'de> Deserialize<'de> for BootId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if !crate::storage_lifecycle::valid_uuid(&s) || s == "00000000-0000-0000-0000-000000000000"
        {
            return Err(serde::de::Error::custom(
                "invalid storage node boot identity",
            ));
        }
        Ok(Self(s))
    }
}

impl BootId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Production provenance comes from Linux, never a pod manifest or request.
    pub(crate) fn current() -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/proc/sys/kernel/random/boot_id")
                .map_err(|_| "cannot observe local kernel boot identity")?;
            let mut value = String::new();
            (&mut f)
                .take(38)
                .read_to_string(&mut value)
                .map_err(|_| "cannot read local kernel boot identity")?;
            if value.len() != 37 || !value.ends_with('\n') {
                return Err("unexpected kernel boot identity framing".into());
            }
            serde_json::from_value(serde_json::Value::String(value.trim_end().into()))
                .map_err(|_| "invalid local kernel boot identity".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("storage agent boot observation requires Linux".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_identity_is_strict_and_never_defaults_to_another_incarnation() {
        for v in [
            "",
            "0",
            "00000000-0000-0000-0000-000000000000",
            "71CB439A-d59b-4d47-9058-2134d97ebd7f",
            "71cb439a-d59b-4d47-9058-2134d97ebd7f\n",
        ] {
            assert!(serde_json::from_value::<BootId>(serde_json::json!(v)).is_err());
        }
        let id: BootId =
            serde_json::from_value(serde_json::json!("71cb439a-d59b-4d47-9058-2134d97ebd7f"))
                .unwrap();
        assert_eq!(id.as_str(), "71cb439a-d59b-4d47-9058-2134d97ebd7f");
        assert!(serde_json::from_str::<BootId>("null").is_err());
    }
}
