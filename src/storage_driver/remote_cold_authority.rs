//! Remote follower authorization is distinct from local leader ColdParent.
//! A ReceiverSession owns exact sequenced one-boundary approval, not a lease
//! to perform arbitrary future IO. No constructor accepts only wire JSON.
use super::*;
use crate::raft_node::storage_remote_core as core;
use crate::storage_remote_protocol::{
    self as protocol, Boundary, JobKind, JobSpec, ReceiverSession, VerifiedDirectory,
};

pub(crate) struct RemoteColdParent {
    shared: Arc<super::super::native_runtime::Shared>,
    session: ReceiverSession,
    spec: JobSpec,
    intent: ProvisionIntent,
    native: Option<live::JobIdentity>,
}
impl RemoteColdParent {
    pub(super) fn lease_owner(&self) -> Arc<super::super::native_runtime::Shared> {
        self.shared.clone()
    }
    pub(crate) async fn establish(
        shared: Arc<super::super::native_runtime::Shared>,
        spec: JobSpec,
    ) -> Result<Self, String> {
        cold_authority::require_actual_cluster_world(shared.world())?;
        if spec.kind != JobKind::PrepareVirginOffline {
            return Err("remote parent is cold-only".into());
        }
        shared.check_config().await?;
        let before = core::observe_local_async(&spec.owner.volume_uid).await?;
        let directory = shared.directory_for(&before)?;
        let (mut session, request) =
            ReceiverSession::challenge(spec.clone(), &before, &directory, Instant::now())?;
        let reply = shared
            .call(
                protocol::GRANT_PATH,
                &request,
                &spec.issuer_node_uid,
                &directory,
            )
            .await?;
        let (minimum, deadline) = session.grant_wait_hint(&reply)?;
        core::wait_applied_hint(&minimum, deadline).await?;
        let local = core::observe_local_async(&spec.owner.volume_uid).await?;
        let current = shared.directory_for(&local)?;
        session.accept(reply, &local, &current, Instant::now())?;
        shared.pipeline_deadline()?;
        shared.shorten_pipeline_deadline(session.accepted_deadline()?)?;
        let intent = crate::storage_controller::from_accepted_cold_receiver(&session, &local)?;
        intent.check_current(shared.world())?;
        Ok(Self {
            shared,
            session,
            spec,
            intent,
            native: None,
        })
    }
    pub(crate) fn intent(&self) -> &ProvisionIntent {
        &self.intent
    }
    pub(super) fn deadline(&self) -> Result<Instant, String> {
        self.shared.pipeline_deadline()?;
        self.session.accepted_cold_spec()?;
        self.session.accepted_deadline()
    }
    pub(super) fn world(&self) -> Arc<RwLock<DesiredWorld>> {
        self.shared.world().clone()
    }
    pub(super) fn binding(&self) -> Result<String, String> {
        Ok(hash(&protocol::encode_node(&self.spec)?))
    }
    pub(super) fn bind_native(&mut self, identity: &live::JobIdentity) -> Result<(), String> {
        if self.native.is_some()
            || identity.node_uid != self.spec.target_node_uid
            || identity.boot_id != self.spec.target_boot.as_str()
            || identity.volume_uid != self.spec.owner.volume_uid
            || identity.operation_uid != self.spec.operation_uid
        {
            return Err("remote parent cannot change native helper lineage".into());
        }
        self.native = Some(identity.clone());
        Ok(())
    }
    pub(super) fn approve(&mut self, request: &live::Request) -> Result<Option<bool>, String> {
        let expected = self
            .native
            .as_ref()
            .ok_or("remote native identity not bound")?;
        let Some(kind) = native_kind(request, expected) else {
            return Ok(Some(false));
        };
        let detail = hash(
            &serde_json::to_vec(request).map_err(|_| "cannot bind exact native cold challenge")?,
        );
        self.fresh(kind, detail)?;
        Ok(Some(true))
    }
    pub(super) fn complete(&mut self, completion: &VerifiedLocalBoundary) -> Result<(), String> {
        self.fresh(Boundary::ColdComplete, completion.binding().to_string())
    }
    fn fresh(&mut self, kind: Boundary, detail: String) -> Result<(), String> {
        let rt = crate::raft_node::RAFT
            .get()
            .ok_or("remote cold actual Raft missing")?
            .rt
            .clone();
        rt.block_on(async {
            self.shared.check_config().await?;
            self.intent.check_current(self.shared.world())?;
            let local = core::observe_local_async(&self.spec.owner.volume_uid).await?;
            let directory = self.shared.directory_for(&local)?;
            let request =
                self.session
                    .boundary(kind, detail.clone(), &local, &directory, Instant::now())?;
            let reply = match self
                .shared
                .call(
                    protocol::BOUNDARY_PATH,
                    &request,
                    &self.spec.issuer_node_uid,
                    &directory,
                )
                .await
            {
                Ok(reply) => reply,
                Err(error) => {
                    self.session.transport_lost();
                    return Err(error);
                }
            };
            let (minimum, deadline) = self.session.boundary_wait_hint(&reply)?;
            core::wait_applied_hint(&minimum, deadline).await?;
            let after = core::observe_local_async(&self.spec.owner.volume_uid).await?;
            let current = self.shared.directory_for(&after)?;
            let token = self
                .session
                .boundary_reply(reply, &after, &current, Instant::now())?;
            self.intent.check_current(self.shared.world())?;
            self.shared.pipeline_deadline()?;
            token.consume(kind, &detail)
        })
    }
}
fn native_kind(request: &live::Request, expected: &live::JobIdentity) -> Option<Boundary> {
    if request.version != 1
        || &request.identity != expected
        || request.sequence == 0
        || !valid_hash(&request.detail_sha256)
    {
        return None;
    }
    Some(match request.boundary.as_str() {
        "helper-start" if request.detail_sha256 == hash(b"native-virgin-offline-only-v2") => {
            Boundary::ColdStart
        }
        "identity-check" => Boundary::ColdIdentity,
        "fixed-program" => Boundary::ColdProgram,
        "zero-write" => Boundary::ColdZeroWrite,
        "zero-fsync" => Boundary::ColdZeroFsync,
        _ => return None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cold_native_whitelist_refuses_online_init_and_changed_lineage() {
        let id = live::JobIdentity {
            node_uid: Uid::new(),
            boot_id: "12345678-1234-4234-a234-123456789abc".into(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        };
        let mut request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "helper-start".into(),
            detail_sha256: hash(b"native-virgin-offline-only-v2"),
        };
        assert_eq!(native_kind(&request, &id), Some(Boundary::ColdStart));
        for other in [
            b"native-secondary-only".as_slice(),
            b"native-initialize-new-only-v2",
        ] {
            request.detail_sha256 = hash(other);
            assert!(native_kind(&request, &id).is_none());
        }
        request.boundary = "format".into();
        request.detail_sha256 = "a".repeat(64);
        assert!(native_kind(&request, &id).is_none());
        request.boundary = "zero-write".into();
        request.identity.attempt_uid = Uid::new();
        assert!(native_kind(&request, &id).is_none());
    }
}
