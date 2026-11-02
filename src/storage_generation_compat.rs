//! Old disk/envelope domains cannot authenticate the later dataset-generation
//! contract. This is a raw pre-deserialization refusal gate, not a migrator.
//! It never invents a generation, receipt, filesystem or writer assignment.
use serde_json::Value;

pub(crate) fn legacy_without_data_authority(raw: &Value) -> Result<(), String> {
    let root = raw.as_object().ok_or("legacy desired state is not an object")?;
    let Some(ids) = root.get("storage_identities") else { return Ok(()); };
    let ids = ids.as_object().ok_or("legacy storage identity graph is malformed")?;
    let Some(registry) = ids.get("lifecycle") else { return Ok(()); };
    let registry = registry.as_object().ok_or("legacy managed-volume history is malformed")?;
    if registry.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("legacy storage lifecycle version cannot import generation authority".into());
    }
    let volumes = registry.get("volumes").and_then(Value::as_object)
        .ok_or("legacy managed-volume inventory is missing or malformed")?;
    for volume in volumes.values() {
        let volume = volume.as_object().ok_or("legacy managed-volume record is malformed")?;
        if volume.get("version").and_then(Value::as_u64) != Some(1)
            || !matches!(volume.get("phase").and_then(Value::as_str),Some("PendingProvision"|"Provisioning"))
            || volume.get("epoch").and_then(Value::as_u64) != Some(0)
        {
            return Err("legacy managed volume has data/writer history; explicit quarantined recovery required".into());
        }
        for key in ["filesystem_uuid","assignment","evidence","data_generation"] {
            if volume.get(key).is_some_and(|value| !value.is_null()) {
                return Err("old state/envelope cannot import filesystem, writer, receipt or dataset authority".into());
            }
        }
        // A future newly shaped field cannot acquire authority by insertion
        // into an old authenticated/serialized domain. Typed current identity
        // validation still runs after this raw refusal check.
        if volume.keys().any(|key| !matches!(key.as_str(),
            "version"|"owner"|"capacity_bytes"|"reclaim_policy"|"phase"|"epoch"|"operation"|
            "replicas"|"provision_boots"|"filesystem_uuid"|"assignment"|"evidence"|"data_generation"))
        {
            return Err("unknown legacy managed-volume field cannot import newer authority".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn safe(phase:&str)->Value { serde_json::json!({"storage_identities":{"version":1,
        "lifecycle":{"version":1,"volumes":{"a":{"version":1,"phase":phase,"epoch":0,
        "filesystem_uuid":null,"assignment":null,"evidence":null}}}}}) }
    #[test] fn absent_or_empty_legacy_lifecycle_has_no_new_authority(){
        for raw in [serde_json::json!({}),serde_json::json!({"storage_identities":{}}),
            serde_json::json!({"storage_identities":{"lifecycle":{"version":1,"volumes":{}}}})] {
            assert!(legacy_without_data_authority(&raw).is_ok());
        }
    }
    #[test] fn only_unwritable_pending_or_prepare_records_pass_raw_gate(){
        for phase in ["PendingProvision","Provisioning"] {
            let raw=safe(phase);let before=raw.clone();
            assert!(legacy_without_data_authority(&raw).is_ok());assert_eq!(raw,before);
        }
    }
    #[test] fn every_later_phase_is_recovery_not_backfill(){
        for phase in ["Detached","Attaching","Attached","Detaching","Fencing","Released","Deleting","Deleted"] {
            let raw=safe(phase);let before=raw.clone();
            assert!(legacy_without_data_authority(&raw).is_err(),"{phase}");assert_eq!(raw,before);
        }
    }
    #[test] fn filesystem_writer_receipt_or_generation_in_old_domain_is_refused(){
        for key in ["filesystem_uuid","assignment","evidence","data_generation"] {
            let mut raw=safe("Provisioning");raw["storage_identities"]["lifecycle"]["volumes"]["a"][key]=serde_json::json!({"plausible":"new-shape"});
            let before=raw.clone();assert!(legacy_without_data_authority(&raw).is_err(),"{key}");assert_eq!(raw,before);
        }
    }
    #[test] fn epoch_and_inner_versions_cannot_be_downgraded_into_old_domain(){
        for (field,value) in [("epoch",1),("version",2)] {
            let mut raw=safe("Provisioning");raw["storage_identities"]["lifecycle"]["volumes"]["a"][field]=value.into();
            assert!(legacy_without_data_authority(&raw).is_err());
        }
        let mut raw=safe("Provisioning");raw["storage_identities"]["lifecycle"]["version"]=2.into();
        assert!(legacy_without_data_authority(&raw).is_err());
    }
    #[test] fn invented_new_init_fields_are_not_authority_in_legacy_envelope(){
        let mut raw=safe("Provisioning");raw["storage_identities"]["lifecycle"]["volumes"]["a"]["initialize_operation"]=serde_json::json!("b".repeat(32));
        assert!(legacy_without_data_authority(&raw).is_err());
    }
    #[test] fn malformed_raw_shape_is_never_empty_history(){
        for raw in [Value::Null,serde_json::json!({"storage_identities":null}),
            serde_json::json!({"storage_identities":{"lifecycle":null}}),
            serde_json::json!({"storage_identities":{"lifecycle":{"version":1}}}),
            serde_json::json!({"storage_identities":{"lifecycle":{"version":1,"volumes":[]}}})] {
            assert!(legacy_without_data_authority(&raw).is_err());
        }
    }
}
