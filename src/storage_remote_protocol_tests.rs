//! Deterministic protocol models: no socket, VM, process, wall-clock sleeps,
//! actual quorum calls, worker or physical receipt. SOURCE ONLY, not run yet.
use super::*;
// Test-only API shim binds a MODEL observation to a model verified frame. It
// never calls actual quorum or makes a production CoreObservation. Negative
// reuse tests below call the real *_bound API without this shim.
trait ModelIssuerApi {
    fn grant(
        peer: VerifiedPeerFrame,
        view: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<(IssuerSession, Vec<u8>), String>;
    fn approve(
        &mut self,
        peer: VerifiedPeerFrame,
        view: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String>;
}
impl ModelIssuerApi for IssuerSession {
    fn grant(
        peer: VerifiedPeerFrame,
        view: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<(IssuerSession, Vec<u8>), String> {
        let bound = view.bind_model_request(&peer);
        Self::grant_bound(peer, &bound, directory, now)
    }
    fn approve(
        &mut self,
        peer: VerifiedPeerFrame,
        view: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        let bound = view.bind_model_request(&peer);
        self.approve_bound(peer, &bound, directory, now)
    }
}
fn model_book_grant(
    book: &mut IssuerBook,
    peer: VerifiedPeerFrame,
    view: &CoreObservation,
    directory: &VerifiedDirectory,
    now: Instant,
) -> Result<Vec<u8>, String> {
    let bound = view.bind_model_request(&peer);
    book.grant(peer, &bound, directory, now)
}
use crate::raft_node::storage_remote_core::model_for_protocol_tests as observe;

fn uid(n: u64) -> Uid {
    serde_json::from_value(serde_json::json!(format!("{n:032x}"))).unwrap()
}
fn boot(n: u64) -> BootId {
    serde_json::from_value(serde_json::json!(format!(
        "{n:08x}-1111-4111-a111-111111111111"
    )))
    .unwrap()
}
struct Model {
    volume: crate::storage_lifecycle::Volume,
    directory: DirectoryDto,
    revision: Revision,
    spec: JobSpec,
    now: Instant,
}
impl Model {
    fn new() -> Self {
        let now = Instant::now();
        let mut world = crate::reconcile::DesiredWorld::new();
        world.cluster_id = "a".repeat(12);
        for raw in [
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"native"},"spec":{"provisioner":crate::storage_lifecycle::PROVISIONER}}),
            serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"team"},"spec":{"storageClassName":"native","resources":{"requests":{"storage":"64Mi"}}}}),
        ] {
            world.apply(&serde_json::from_value(raw).unwrap()).unwrap();
        }
        let volume_uid = world.storage_identities.volumes
            [world.pvcs["team/data"].bound_pv.as_ref().unwrap()]
        .clone();
        let volume = world
            .storage_identities
            .lifecycle
            .get_mut(&volume_uid)
            .unwrap();
        volume
            .begin_provision(
                [uid(1), uid(2), uid(3)],
                [boot(1), boot(2), boot(3)],
                uid(10),
            )
            .unwrap();
        let volume = volume.clone();
        let directory = DirectoryDto {
            version: 1,
            cluster_id: world.cluster_id.clone(),
            nodes: (1..=3)
                .map(|n| NodePin {
                    node_uid: uid(n),
                    raft_id: n,
                    signer_name: format!("node{n}"),
                    wireguard_key: format!(
                        "{}{}=",
                        "A".repeat(42),
                        ["E", "I", "M"][n as usize - 1]
                    ),
                    wireguard_ip: format!("10.77.0.{n}").parse().unwrap(),
                })
                .collect(),
        };
        let revision = Revision {
            term: 7,
            leader_raft_id: 1,
            applied_term: 7,
            applied_leader_raft_id: 1,
            applied_index: 50,
            desired_generation: 41,
            membership_sha256: "a".repeat(64),
        };
        let spec = JobSpec {
            version: 1,
            owner: volume.owner().clone(),
            operation_uid: uid(10),
            dataset_uid: None,
            kind: JobKind::PrepareClosedSecondary,
            issuer_node_uid: uid(1),
            issuer_boot: boot(1),
            target_node_uid: uid(2),
            target_boot: boot(2),
            job_uid: uid(20),
            plan_sha256: "c".repeat(64),
            scope_sha256: "b".repeat(64),
            directory_sha256: hash(&encode(&directory).unwrap()),
            issuer_revision: revision.clone(),
            maximum_duration_ms: 900_000,
            initialization: None,
        };
        Self {
            volume,
            directory,
            revision,
            spec,
            now,
        }
    }
    fn view(&self, node: u64, issuer: bool, now: Instant) -> CoreObservation {
        observe(
            self.volume.clone(),
            self.revision.clone(),
            uid(node),
            boot(node),
            "b".repeat(64),
            Some(hash(&encode(&self.directory).unwrap())),
            now,
            issuer,
        )
    }
    fn directory(&self) -> VerifiedDirectory {
        VerifiedDirectory::from_core(&self.view(2, false, self.now), self.directory.clone())
            .unwrap()
    }
    fn receiver(&self) -> (ReceiverSession, Vec<u8>) {
        ReceiverSession::challenge(
            self.spec.clone(),
            &self.view(2, false, self.now),
            &self.directory(),
            self.now,
        )
        .unwrap()
    }
}
fn frame(sender: u64, receiver: u64, body: Vec<u8>) -> VerifiedPeerFrame {
    VerifiedPeerFrame {
        sender: uid(sender),
        receiver: uid(receiver),
        body,
    }
}
fn accepted(model: &Model) -> (ReceiverSession, IssuerSession) {
    let (mut client, request) = model.receiver();
    let (server, response) = IssuerSession::grant(
        frame(2, 1, request),
        &model.view(1, true, model.now),
        &model.directory(),
        model.now,
    )
    .unwrap();
    client
        .accept(
            frame(1, 2, response),
            &model.view(2, false, model.now),
            &model.directory(),
            model.now,
        )
        .unwrap();
    (client, server)
}
#[test]
fn original_pipeline_remaining_budget_is_not_restarted_by_a_late_grant() {
    let start = Instant::now();
    let original = start + Duration::from_secs(180);
    let late = start + Duration::from_secs(80);
    let (deadline, remaining) = bounded_grant_deadline(late, 180_000, Some(original)).unwrap();
    assert_eq!(deadline, original);
    assert_eq!(remaining, 100_000);
    assert!(bounded_grant_deadline(original, 180_000, Some(original)).is_err());
    assert!(
        bounded_grant_deadline(original + Duration::from_secs(1), 180_000, Some(original)).is_err()
    );
    let (shorter, remaining) = bounded_grant_deadline(late, 1000, Some(original)).unwrap();
    assert_eq!(shorter, late + Duration::from_secs(1));
    assert_eq!(remaining, 1000);
}
#[test]
fn accepted_receiver_anchors_shortened_grant_to_challenge_start_not_receipt() {
    let m = Model::new();
    let (mut receiver, request) = m.receiver();
    let peer = frame(2, 1, request);
    let issuer = m.view(1, true, m.now).bind_model_request(&peer);
    let original = m.now + Duration::from_millis(500);
    let (server, response) =
        IssuerSession::grant_bound_deadline(peer, &issuer, &m.directory(), m.now, Some(original))
            .unwrap();
    let receipt = m.now + Duration::from_millis(200);
    receiver
        .accept(
            frame(1, 2, response),
            &m.view(2, false, receipt),
            &m.directory(),
            receipt,
        )
        .unwrap();
    assert_eq!(server.deadline, original);
    assert_eq!(receiver.deadline, original);
    assert_ne!(receiver.deadline, receipt + Duration::from_millis(500));
    assert_eq!(receiver.accepted_deadline_at(m.now).unwrap(), original);
    assert!(receiver.accepted_deadline_at(original).is_err());
    receiver.transport_lost();
    assert!(receiver.accepted_deadline_at(m.now).is_err());
}

#[test]
fn schema7_without_identity_directory_cannot_mint_a_verified_pin_map() {
    let m = Model::new();
    let view = observe(
        m.volume,
        m.revision,
        uid(2),
        boot(2),
        "b".repeat(64),
        None,
        m.now,
        false,
    );
    assert!(VerifiedDirectory::from_core(&view, m.directory).is_err());
}
#[test]
fn directory_rejects_every_ambiguous_member_identity() {
    let m = Model::new();
    m.directory.validate().unwrap();
    for case in 0..8 {
        let mut bad = m.directory.clone();
        match case {
            0 => bad.nodes[1].node_uid = bad.nodes[0].node_uid.clone(),
            1 => bad.nodes[1].raft_id = bad.nodes[0].raft_id,
            2 => bad.nodes[1].signer_name = bad.nodes[0].signer_name.clone(),
            3 => bad.nodes[1].wireguard_key = bad.nodes[0].wireguard_key.clone(),
            4 => bad.nodes[1].wireguard_ip = bad.nodes[0].wireguard_ip,
            5 => bad.nodes.pop().map(|_| ()).unwrap(),
            6 => bad.nodes[1].raft_id = 0,
            _ => bad.nodes[1].wireguard_ip = "192.0.2.10".parse().unwrap(),
        }
        assert!(bad.validate().is_err(), "case{case}");
    }
}
#[test]
fn wireguard_requires_exact_disjoint_registered_slash32_peers() {
    let m = Model::new();
    let d = m.directory();
    let good = format!(
        "{}\t10.77.0.1/32\n{}\t10.77.0.3/32\n",
        m.directory.nodes[0].wireguard_key, m.directory.nodes[2].wireguard_key
    );
    crate::storage_driver::remote_transport::allowed_ips_model(&good, &d, &uid(2)).unwrap();
    for bad in [
        good.replace("10.77.0.1/32", "0.0.0.0/0"),
        good.replace("10.77.0.1/32", "10.77.0.1/24"),
        good.replace("10.77.0.1/32", "10.77.0.1/32,10.77.0.2/32"),
        good.lines().next().unwrap().into(),
        format!(
            "{good}{}\t10.77.0.1/32\n",
            m.directory.nodes[0].wireguard_key
        ),
        good.replace("10.77.0.3/32", "10.77.0.1/32"),
    ] {
        assert!(
            crate::storage_driver::remote_transport::allowed_ips_model(&bad, &d, &uid(2)).is_err()
        );
    }
}
#[test]
fn revision_never_accepts_new_term_leader_membership_or_log_alias() {
    let m = Model::new();
    assert!(m.revision.at_least(&m.revision));
    for case in 0..7 {
        let mut bad = m.revision.clone();
        match case {
            0 => bad.term += 1,
            1 => bad.leader_raft_id = 2,
            2 => bad.membership_sha256 = "d".repeat(64),
            3 => bad.applied_index -= 1,
            4 => bad.desired_generation -= 1,
            5 => bad.applied_leader_raft_id = 2,
            _ => bad.applied_term -= 1,
        }
        assert!(!bad.at_least(&m.revision), "case{case}");
    }
}
#[test]
fn typed_roundtrip_requires_a_new_nonce_and_fresh_leader_barrier_for_each_boundary() {
    let m = Model::new();
    let (mut client, mut server) = accepted(&m);
    for (index, kind) in [Boundary::ReadInventory, Boundary::CreateNewMetadata]
        .into_iter()
        .enumerate()
    {
        let now = m.now + Duration::from_millis(index as u64 * 10);
        let request = client
            .boundary(
                kind,
                "d".repeat(64),
                &m.view(2, false, now),
                &m.directory(),
                now,
            )
            .unwrap();
        let reply = server
            .approve(
                frame(2, 1, request),
                &m.view(1, true, now),
                &m.directory(),
                now,
            )
            .unwrap();
        let one = client
            .boundary_reply(
                frame(1, 2, reply),
                &m.view(2, false, now),
                &m.directory(),
                now,
            )
            .unwrap();
        one.consume_at(kind, &"d".repeat(64), now).unwrap();
    }
    assert_eq!(client.next_sequence, 3);
    assert_eq!(server.next_sequence, 3);
}
#[test]
fn follower_or_cached_aged_observation_cannot_approve_a_remote_action() {
    let m = Model::new();
    let (_, request) = m.receiver();
    assert!(IssuerSession::grant(
        frame(2, 1, request.clone()),
        &m.view(1, false, m.now),
        &m.directory(),
        m.now
    )
    .is_err());
    assert!(IssuerSession::grant(
        frame(2, 1, request),
        &m.view(1, true, m.now),
        &m.directory(),
        m.now + Duration::from_millis(MAX_BOUNDARY_MS + 1)
    )
    .is_err());
}
#[test]
fn grant_replay_or_wrong_peer_closes_the_exact_receiver_session() {
    let m = Model::new();
    let (mut c, request) = m.receiver();
    let (_, reply) = IssuerSession::grant(
        frame(2, 1, request),
        &m.view(1, true, m.now),
        &m.directory(),
        m.now,
    )
    .unwrap();
    c.accept(
        frame(1, 2, reply.clone()),
        &m.view(2, false, m.now),
        &m.directory(),
        m.now,
    )
    .unwrap();
    assert!(c
        .accept(
            frame(1, 2, reply),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
    assert!(c.closed);
    let (_, request) = m.receiver();
    assert!(IssuerSession::grant(
        frame(3, 1, request),
        &m.view(1, true, m.now),
        &m.directory(),
        m.now
    )
    .is_err());
}
#[test]
fn matching_node_name_never_substitutes_for_target_uid_or_boot() {
    let m = Model::new();
    for (node, boot_id) in [(uid(3), boot(2)), (uid(2), boot(3))] {
        let local = observe(
            m.volume.clone(),
            m.revision.clone(),
            node,
            boot_id,
            "b".repeat(64),
            Some(m.spec.directory_sha256.clone()),
            m.now,
            false,
        );
        assert!(ReceiverSession::challenge(m.spec.clone(), &local, &m.directory(), m.now).is_err());
    }
}
#[test]
fn local_state_lag_requires_catchup_not_trusting_the_leader_projection() {
    let m = Model::new();
    let (mut client, request) = m.receiver();
    let (mut _server, reply) = IssuerSession::grant(
        frame(2, 1, request),
        &m.view(1, true, m.now),
        &m.directory(),
        m.now,
    )
    .unwrap();
    let mut behind = m.revision.clone();
    behind.applied_index -= 1;
    behind.desired_generation -= 1;
    let local = observe(
        m.volume.clone(),
        behind,
        uid(2),
        boot(2),
        "b".repeat(64),
        Some(m.spec.directory_sha256.clone()),
        m.now,
        false,
    );
    assert!(client
        .accept(frame(1, 2, reply), &local, &m.directory(), m.now)
        .is_err());
    assert!(client.closed);
}
#[test]
fn no_overlapping_boundary_pipeline_or_replayed_approval() {
    let m = Model::new();
    let (mut client, mut server) = accepted(&m);
    let request = client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let reply = server
        .approve(
            frame(2, 1, request.clone()),
            &m.view(1, true, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    assert!(server
        .approve(
            frame(2, 1, request),
            &m.view(1, true, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
    assert!(server.closed);
    client
        .boundary_reply(
            frame(1, 2, reply.clone()),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    assert!(client
        .boundary_reply(
            frame(1, 2, reply),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
    let (mut c, _) = accepted(&m);
    c.boundary(
        Boundary::Checkpoint,
        "e".repeat(64),
        &m.view(2, false, m.now),
        &m.directory(),
        m.now,
    )
    .unwrap();
    assert!(c
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
    assert!(c.closed);
}
#[test]
fn scope_removal_permanently_closes_session_even_if_old_values_reappear() {
    let m = Model::new();
    let (mut c, _) = accepted(&m);
    let changed = observe(
        m.volume.clone(),
        m.revision.clone(),
        uid(2),
        boot(2),
        "e".repeat(64),
        Some(m.spec.directory_sha256.clone()),
        m.now,
        false,
    );
    assert!(c
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &changed,
            &m.directory(),
            m.now
        )
        .is_err());
    assert!(c
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
}
#[test]
fn delay_or_transport_loss_never_renews_deadline_or_reopens_a_session() {
    let m = Model::new();
    let (mut c, mut s) = accepted(&m);
    let original = c.deadline;
    let request = c
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let reply = s
        .approve(
            frame(2, 1, request),
            &m.view(1, true, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let late = m.now + Duration::from_millis(MAX_BOUNDARY_MS + 1);
    assert!(c
        .boundary_reply(
            frame(1, 2, reply),
            &m.view(2, false, late),
            &m.directory(),
            late
        )
        .is_err());
    assert!(c.deadline <= original);
    let (mut c, _) = accepted(&m);
    c.transport_lost();
    assert!(c.closed);
    assert!(c
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
}
#[test]
fn fresh_global_revision_may_advance_but_scope_term_membership_cannot_change() {
    let m = Model::new();
    let (mut client, mut server) = accepted(&m);
    let mut current = m.revision.clone();
    current.applied_index += 1;
    current.desired_generation += 1;
    let view = |node, issuer| {
        observe(
            m.volume.clone(),
            current.clone(),
            uid(node),
            boot(node),
            "b".repeat(64),
            Some(m.spec.directory_sha256.clone()),
            m.now,
            issuer,
        )
    };
    let request = client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &view(2, false),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let reply = server
        .approve(frame(2, 1, request), &view(1, true), &m.directory(), m.now)
        .unwrap();
    client
        .boundary_reply(frame(1, 2, reply), &view(2, false), &m.directory(), m.now)
        .unwrap();
}
#[test]
fn initialization_and_arbitrary_commands_are_not_remote_job_capabilities() {
    let mut m = Model::new();
    m.spec.kind = JobKind::InitializeVirginGeneration;
    m.spec.dataset_uid = Some(uid(99));
    assert!(m.receiver_error());
    assert!(!Boundary::PrepareNewBacking.permits(JobKind::ObserveVirginReplica));
    let raw = serde_json::json!({"kind":"RunShell","command":"mkfs /dev/foreign"});
    assert!(decode::<BoundaryRequest>(&raw.to_string().into_bytes()).is_err());
}
impl Model {
    fn receiver_error(&self) -> bool {
        ReceiverSession::challenge(
            self.spec.clone(),
            &self.view(2, false, self.now),
            &self.directory(),
            self.now,
        )
        .is_err()
    }
}
#[test]
fn expired_or_closed_admission_does_not_clear_an_unknown_node_job() {
    let m = Model::new();
    let (_, request) = m.receiver();
    let mut book = IssuerBook::new();
    model_book_grant(
        &mut book,
        frame(2, 1, request.clone()),
        &m.view(1, true, m.now),
        &m.directory(),
        m.now,
    )
    .unwrap();
    book.transport_lost(&uid(2));
    assert_eq!(book.nodes.len(), 1);
    let later = m.now + Duration::from_millis(MAX_JOB_MS + 1);
    assert!(model_book_grant(
        &mut book,
        frame(2, 1, request),
        &m.view(1, true, later),
        &m.directory(),
        later
    )
    .is_err());
    assert_eq!(book.nodes.len(), 1);
}
#[test]
fn strict_bounded_dtos_do_not_ignore_future_authority_fields() {
    let m = Model::new();
    let (_, request) = m.receiver();
    let mut raw: serde_json::Value = serde_json::from_slice(&request).unwrap();
    raw["writer_uid"] = serde_json::json!(uid(123));
    assert!(decode::<GrantRequest>(&serde_json::to_vec(&raw).unwrap()).is_err());
    assert!(decode::<GrantRequest>(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    assert!(decode::<GrantRequest>(b"{}").is_err());
}

fn one_pending_token(m: &Model) -> (ReceiverSession, IssuerSession, OneBoundary) {
    let (mut client, mut server) = accepted(m);
    let request = client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let reply = server
        .approve(
            frame(2, 1, request),
            &m.view(1, true, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let one = client
        .boundary_reply(
            frame(1, 2, reply),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    (client, server, one)
}
#[test]
fn transport_revocation_after_mint_denies_the_already_outstanding_boundary() {
    let m = Model::new();
    let (mut client, _, one) = one_pending_token(&m);
    client.transport_lost();
    assert!(one
        .consume_at(Boundary::Checkpoint, &"e".repeat(64), m.now)
        .is_err());
    assert!(client.revoked());
}
#[test]
fn unconsumed_or_abandoned_token_cannot_overlap_another_action() {
    let m = Model::new();
    let (mut client, _, one) = one_pending_token(&m);
    assert!(client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
    assert!(one
        .consume_at(Boundary::Checkpoint, &"e".repeat(64), m.now)
        .is_err());
    let (mut client, _, one) = one_pending_token(&m);
    drop(one);
    assert!(client.revoked());
    assert!(client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now
        )
        .is_err());
}
#[test]
fn previous_quorum_barrier_cannot_approve_a_different_sequential_request() {
    let m = Model::new();
    let (mut client, mut server) = accepted(&m);
    let request = client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    let first = frame(2, 1, request);
    let observed = m.view(1, true, m.now).bind_model_request(&first);
    let reply = server
        .approve_bound(first, &observed, &m.directory(), m.now)
        .unwrap();
    let one = client
        .boundary_reply(
            frame(1, 2, reply),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    one.consume_at(Boundary::Checkpoint, &"e".repeat(64), m.now)
        .unwrap();
    let next = client
        .boundary(
            Boundary::Checkpoint,
            "e".repeat(64),
            &m.view(2, false, m.now),
            &m.directory(),
            m.now,
        )
        .unwrap();
    assert!(
        server
            .approve_bound(frame(2, 1, next), &observed, &m.directory(), m.now)
            .is_err(),
        "same-age but different-request observation is not fresh authority"
    );
    assert!(server.closed);
}
#[test]
fn unbound_underlay_flow_is_not_authenticated_by_matching_ip_names() {
    use crate::storage_driver::remote_transport::bound_listener_model as check;
    check("wg-storage", "wg-storage", 7, 7).unwrap();
    for (device, index, current) in [
        ("", 7, 7),
        ("eth0", 7, 7),
        ("wg-storage", 0, 7),
        ("wg-storage", 7, 8),
    ] {
        assert!(
            check("wg-storage", device, index, current).is_err(),
            "matching IP or name cannot replace accepted device-bound context"
        );
    }
}
#[test]
fn dropping_receiver_after_mint_revokes_its_token_too() {
    let m = Model::new();
    let (client, _, one) = one_pending_token(&m);
    drop(client);
    assert!(one
        .consume_at(Boundary::Checkpoint, &"e".repeat(64), m.now)
        .is_err());
}

// Normal-runtime pure protocol models only; no physical or actual Core proof.
#[test]
fn normal_cold_kind_cannot_authorize_activation_or_initializer_boundaries() {
    for boundary in [
        Boundary::ColdStart,
        Boundary::ColdIdentity,
        Boundary::ColdProgram,
        Boundary::ColdZeroWrite,
        Boundary::ColdZeroFsync,
        Boundary::ColdComplete,
    ] {
        assert!(boundary.permits(JobKind::PrepareVirginOffline));
        assert!(!boundary.permits(JobKind::PrepareClosedSecondary));
        assert!(!boundary.permits(JobKind::InitializeVirginGeneration));
    }
    for boundary in [
        Boundary::ActivateClosedSecondary,
        Boundary::CreateNewMetadata,
        Boundary::PrepareNewBacking,
        Boundary::ObserveVirgin,
    ] {
        assert!(!boundary.permits(JobKind::PrepareVirginOffline));
    }
}
#[test]
fn normal_cold_full_expected_spec_refuses_plan_or_job_swap_even_when_core_matches() {
    let mut model = Model::new();
    model.spec.kind = JobKind::PrepareVirginOffline;
    model.spec.maximum_duration_ms = 180_000;
    let expected = ExpectedColdJob {
        spec: model.spec.clone(),
    }; // explicit model, no runtime constructor
    let (session, request) = model.receiver();
    assert!(
        session.accepted_cold_spec().is_err(),
        "offer/challenge is not accepted authority"
    );
    expected.require_request(&frame(2, 1, request)).unwrap();
    for changed in ["plan", "job"] {
        let mut spec = model.spec.clone();
        if changed == "plan" {
            spec.plan_sha256 = "d".repeat(64);
        } else {
            spec.job_uid = Uid::new();
        }
        assert!(
            spec.current(&model.view(2, false, model.now), &model.directory())
                .is_ok(),
            "this exercises the extra expected-job join, not merely stale Core"
        );
        let request = encode(&GrantRequest {
            version: 1,
            spec,
            receiver_nonce: Uid::new(),
        })
        .unwrap();
        assert!(expected.require_request(&frame(2, 1, request)).is_err());
    }
}
#[test]
fn normal_cold_job_cannot_extend_180s_budget_and_old_profile_is_unchanged() {
    let mut model = Model::new();
    model.spec.validate().unwrap(); // existing closed-secondary 900s profile
    model.spec.kind = JobKind::PrepareVirginOffline;
    assert!(model.spec.validate().is_err());
    model.spec.maximum_duration_ms = 180_000;
    model.spec.validate().unwrap();
    model.spec.maximum_duration_ms = 180_001;
    assert!(model.spec.validate().is_err());
}
#[test]
fn normal_node_job_wire_is_closed_and_never_a_grant_message() {
    for value in [
        serde_json::json!({"kind":"InspectReadiness","nonce":uid(1),"device":"/dev/vdb"}),
        serde_json::json!({"kind":"StartWriter","nonce":uid(1)}),
        serde_json::json!({"kind":"InspectHeld","job_uid":uid(1),"spec_sha256":"a".repeat(64),"grant_uid":uid(2)}),
    ] {
        assert!(decode_node::<NodeJobRequest>(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let raw = encode_node(&NodeJobRequest::InspectReadiness {
        nonce: uid(1),
        expected: None,
    })
    .unwrap();
    assert!(decode::<GrantRequest>(&raw).is_err());
}

#[test]
fn grant_apply_hint_does_not_renew_deadline_or_accept_lagged_core() {
    let model = Model::new();
    let (mut client, request) = model.receiver();
    let (_, reply) = IssuerSession::grant(
        frame(2, 1, request),
        &model.view(1, true, model.now),
        &model.directory(),
        model.now,
    )
    .unwrap();
    let late = model.now + Duration::from_millis(900);
    let peer = frame(1, 2, reply.clone());
    let mut malformed: GrantReply = decode(&reply).unwrap();
    malformed.remaining_ms = u64::MAX;
    assert!(client
        .grant_wait_hint_at(&frame(1, 2, encode(&malformed).unwrap()), late)
        .is_err());
    let (revision, deadline) = client.grant_wait_hint_at(&peer, late).unwrap();
    assert_eq!(revision, model.revision);
    assert_eq!(deadline, model.now + Duration::from_millis(MAX_BOUNDARY_MS));
    assert!(client.grant.is_none(), "read hint cannot accept a grant");
    let mut old = model.revision.clone();
    old.applied_index -= 1;
    let lagged = observe(
        model.volume.clone(),
        old,
        uid(2),
        boot(2),
        "b".repeat(64),
        Some(model.directory.sha256().unwrap()),
        late,
        false,
    );
    assert!(client
        .accept(peer, &lagged, &model.directory(), late)
        .is_err());
    let (mut client, request) = model.receiver();
    let (_, reply) = IssuerSession::grant(
        frame(2, 1, request),
        &model.view(1, true, model.now),
        &model.directory(),
        model.now,
    )
    .unwrap();
    client
        .accept(
            frame(1, 2, reply),
            &model.view(2, false, late),
            &model.directory(),
            late,
        )
        .unwrap();
    assert!(client.grant.is_some());
}
#[test]
fn boundary_apply_hint_keeps_original_remaining_budget_and_late_reply_is_denied() {
    let model = Model::new();
    let (mut client, mut issuer) = accepted(&model);
    let request = client
        .boundary(
            Boundary::Checkpoint,
            "a".repeat(64),
            &model.view(2, false, model.now),
            &model.directory(),
            model.now,
        )
        .unwrap();
    let reply = issuer
        .approve(
            frame(2, 1, request),
            &model.view(1, true, model.now),
            &model.directory(),
            model.now,
        )
        .unwrap();
    let peer = frame(1, 2, reply);
    let (_, deadline) = client
        .boundary_wait_hint_at(&peer, model.now + Duration::from_millis(900))
        .unwrap();
    assert_eq!(deadline, model.now + Duration::from_millis(MAX_BOUNDARY_MS));
    assert!(
        client.gate.lock().unwrap().authorized.is_none(),
        "hint cannot mint OneBoundary"
    );
    assert!(client
        .boundary_reply(
            peer,
            &model.view(2, false, model.now),
            &model.directory(),
            model.now + Duration::from_millis(MAX_BOUNDARY_MS + 1)
        )
        .is_err());
}
