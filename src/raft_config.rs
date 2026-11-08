//! Construct the existing pinned Raft configuration
//! without using OpenRaft's command-line parser during production startup.
//!
//! All fields are explicit on purpose: an added upstream field must fail to
//! compile and receive review rather than silently adopt a new default.

#[allow(deprecated)] // Preserve pinned OpenRaft 0.9.24's legacy field unchanged.
pub fn raft_config() -> Result<
    std::sync::Arc<openraft::Config>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    Ok(std::sync::Arc::new(openraft::Config {
        cluster_name: "royak".to_string(),
        election_timeout_min: 1000,
        election_timeout_max: 2000,
        heartbeat_interval: 250,
        install_snapshot_timeout: 200,
        send_snapshot_timeout: 0,
        max_payload_entries: 300,
        replication_lag_threshold: 5000,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(64),
        snapshot_max_chunk_size: 3 * 1024 * 1024,
        max_in_snapshot_log_to_keep: 16,
        purge_batch_size: 1,
        enable_tick: true,
        enable_heartbeat: true,
        enable_elect: true,
    }.validate()?))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::raft_config;

    // The legacy parser is deliberately reachable ONLY in test builds.
    // This is the exact configuration expression from the retained root baseline.
    fn legacy_parser_config() -> openraft::Config {
        openraft::Config {
            cluster_name: "royak".to_string(),
            heartbeat_interval: 250,
            election_timeout_min: 1000,
            election_timeout_max: 2000,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(64),
            max_in_snapshot_log_to_keep: 16,
            ..Default::default()
        }.validate().unwrap()
    }

    #[test]
    fn every_pinned_field_matches_the_legacy_parser_result() {
        let actual = raft_config().unwrap();
        let expected = legacy_parser_config();
        macro_rules! equal_fields {
            ($($field:ident),+ $(,)?) => {
                $(assert_eq!(&actual.$field, &expected.$field, stringify!($field));)+
            };
        }
        equal_fields!(
            cluster_name, election_timeout_min, election_timeout_max,
            heartbeat_interval, install_snapshot_timeout, send_snapshot_timeout,
            max_payload_entries, replication_lag_threshold, snapshot_policy,
            snapshot_max_chunk_size, max_in_snapshot_log_to_keep, purge_batch_size,
            enable_tick, enable_heartbeat, enable_elect,
        );
    }

    #[test]
    fn complete_serialized_configuration_matches_without_missing_fields() {
        let actual = serde_json::to_value(raft_config().unwrap().as_ref()).unwrap();
        let expected = serde_json::to_value(legacy_parser_config()).unwrap();
        assert_eq!(actual, expected);
        let fields = actual.as_object().unwrap();
        assert_eq!(fields.len(), 15);
        for name in [
            "cluster_name", "election_timeout_min", "election_timeout_max",
            "heartbeat_interval", "install_snapshot_timeout", "send_snapshot_timeout",
            "max_payload_entries", "replication_lag_threshold", "snapshot_policy",
            "snapshot_max_chunk_size", "max_in_snapshot_log_to_keep", "purge_batch_size",
            "enable_tick", "enable_heartbeat", "enable_elect",
        ] {
            assert!(fields.contains_key(name), "missing field: {name}");
        }
    }

    #[test]
    fn all_existing_timers_limits_and_enable_flags_are_unchanged() {
        let actual = raft_config().unwrap();
        assert_eq!(actual.cluster_name, "royak");
        assert_eq!(actual.election_timeout_min, 1000);
        assert_eq!(actual.election_timeout_max, 2000);
        assert_eq!(actual.heartbeat_interval, 250);
        assert_eq!(actual.install_snapshot_timeout, 200);
        assert_eq!(actual.send_snapshot_timeout, 0);
        assert_eq!(actual.max_payload_entries, 300);
        assert_eq!(actual.replication_lag_threshold, 5000);
        assert_eq!(actual.snapshot_policy, openraft::SnapshotPolicy::LogsSinceLast(64));
        assert_eq!(actual.snapshot_max_chunk_size, 3_145_728);
        assert_eq!(actual.max_in_snapshot_log_to_keep, 16);
        assert_eq!(actual.purge_batch_size, 1);
        assert!(actual.enable_tick);
        assert!(actual.enable_heartbeat);
        assert!(actual.enable_elect);
    }

    fn validation_result(config: openraft::Config) -> Result<serde_json::Value, String> {
        config.validate()
            .map(|value| serde_json::to_value(value).unwrap())
            .map_err(|error| error.to_string())
    }

    #[test]
    fn validation_behavior_remains_identical_for_valid_and_invalid_configs() {
        let actual = raft_config().unwrap();
        let expected = legacy_parser_config();
        assert_eq!(validation_result(actual.as_ref().clone()), validation_result(expected.clone()));
        let changes: [fn(&mut openraft::Config); 3] = [
            |value| value.election_timeout_max = value.election_timeout_min,
            |value| value.heartbeat_interval = value.election_timeout_min,
            |value| value.max_payload_entries = 0,
        ];
        for change in changes {
            let mut candidate = actual.as_ref().clone();
            let mut legacy = expected.clone();
            change(&mut candidate);
            change(&mut legacy);
            let left = validation_result(candidate);
            let right = validation_result(legacy);
            assert!(left.is_err());
            assert_eq!(left, right);
        }
    }

    #[test]
    fn repeated_direct_construction_has_identical_semantics() {
        let first = raft_config().unwrap();
        let second = raft_config().unwrap();
        assert!(!std::sync::Arc::ptr_eq(&first, &second));
        assert_eq!(serde_json::to_value(first.as_ref()).unwrap(),
            serde_json::to_value(second.as_ref()).unwrap());
    }
}
