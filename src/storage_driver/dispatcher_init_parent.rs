//! No follower/local fallback. Every inherited init boundary is re-authorized
//! by actual Core and the exact current controller phase, inside original time.
use super::*;
use crate::raft_node::storage_remote_core as core;
use crate::storage_remote_protocol::{
    self as protocol, Boundary, JobSpec, ReceiverSession, VerifiedDirectory,
};

pub(in crate::storage_driver) enum InitParent {
    Local(Local),
    Remote(Remote),
}
pub(super) struct Local {
    shared: Arc<super::super::super::native_runtime::Shared>,
    owner: std::sync::Weak<HeldInitializationOwner>,
    scope: ExpectedInitScope,
    identity: Option<live::JobIdentity>,
}
pub(super) struct Remote {
    shared: Arc<super::super::super::native_runtime::Shared>,
    owner: std::sync::Weak<HeldInitializationOwner>,
    scope: ExpectedInitScope,
    session: ReceiverSession,
    identity: Option<live::JobIdentity>,
}
pub(crate) fn scope_current(
    scope: &ExpectedInitScope,
    observed: &core::CoreObservation,
    directory: &VerifiedDirectory,
) -> Result<(), String> {
    scope.validate()?;
    let volume = observed.volume();
    if volume.owner() != &scope.owner
        || volume.operation() != &scope.generation.initialize_operation_uid
        || volume.data_generation() != Some(&scope.generation)
        || volume.phase() != crate::storage_lifecycle::Phase::Provisioning
        || volume.epoch() != 0
        || volume.assignment().is_some()
        || observed.scope_sha256() != scope.scope_sha256
        || directory.digest() != scope.directory_sha256
        || observed.local_node_uid() != Some(&scope.target_node_uid)
        || observed.actual_boot() != &scope.target_boot
        || !observed.revision().at_least(&scope.issuer_revision)
        || directory.pin(&scope.issuer_node_uid)?.raft_id != scope.issuer_revision.leader_raft_id
    {
        return Err(
            "initialization phase no longer matches exact applied Core/directory/leader/boot"
                .into(),
        );
    }
    Ok(())
}
impl InitParent {
    pub(in crate::storage_driver) async fn establish_local(
        shared: Arc<super::super::super::native_runtime::Shared>,
        owner: &Arc<HeldInitializationOwner>,
        scope: ExpectedInitScope,
        intent: &InitializationIntent,
    ) -> Result<Self, String> {
        cold_authority::require_actual_cluster_world(shared.world())?;
        shared.check_config().await?;
        let view = core::runtime_view(true).await?;
        let observed = core::observe_local_async(&scope.owner.volume_uid).await?;
        let directory = shared.directory_for(&observed)?;
        scope_current(&scope, &observed, &directory)?;
        if view.local() != &scope.issuer_node_uid
            || scope.target_node_uid != scope.issuer_node_uid
            || view.boot() != &scope.issuer_boot
            || !observed.revision().at_least(view.revision())
            || !intent.matches(observed.volume())
        {
            return Err("local init parent is not the actual quorum leader/target".into());
        }
        owner.install_committed_intent(intent)?;
        Ok(Self::Local(Local {
            shared,
            owner: Arc::downgrade(owner),
            scope,
            identity: None,
        }))
    }
    pub(in crate::storage_driver) async fn establish_remote(
        shared: Arc<super::super::super::native_runtime::Shared>,
        owner: &Arc<HeldInitializationOwner>,
        spec: JobSpec,
    ) -> Result<(Self, InitializationIntent), String> {
        cold_authority::require_actual_cluster_world(shared.world())?;
        shared.check_config().await?;
        let scope = spec
            .initialization
            .as_ref()
            .ok_or("exact phase scope absent")?
            .clone();
        let before = core::observe_local_async(&scope.owner.volume_uid).await?;
        let directory = shared.directory_for(&before)?;
        let (mut session, request) =
            ReceiverSession::challenge(spec, &before, &directory, Instant::now())?;
        let reply = shared
            .call(
                protocol::GRANT_PATH,
                &request,
                &scope.issuer_node_uid,
                &directory,
            )
            .await?;
        let (minimum, deadline) = session.grant_wait_hint(&reply)?;
        core::wait_applied_hint(&minimum, deadline.min(owner.deadline())).await?;
        let after = core::observe_local_async(&scope.owner.volume_uid).await?;
        let current = shared.directory_for(&after)?;
        session.accept(reply, &after, &current, Instant::now())?;
        scope_current(&scope, &after, &current)?;
        let intent = InitializationIntent::from_accepted_distributed_receiver(&session, &after)?;
        owner.install_committed_intent(&intent)?;
        Ok((
            Self::Remote(Remote {
                shared,
                owner: Arc::downgrade(owner),
                scope,
                session,
                identity: None,
            }),
            intent,
        ))
    }
    fn pieces(
        &self,
    ) -> (
        &Arc<super::super::super::native_runtime::Shared>,
        &std::sync::Weak<HeldInitializationOwner>,
        &ExpectedInitScope,
        &Option<live::JobIdentity>,
    ) {
        match self {
            Self::Local(value) => (&value.shared, &value.owner, &value.scope, &value.identity),
            Self::Remote(value) => (&value.shared, &value.owner, &value.scope, &value.identity),
        }
    }
    pub(super) fn binding(&self) -> Result<String, String> {
        Ok(hash(
            &serde_json::to_vec(&("distributed-init-parent-v4", self.pieces().2))
                .map_err(|_| "cannot bind inherited init parent")?,
        ))
    }
    pub(super) fn bind_native(&mut self, identity: &live::JobIdentity) -> Result<(), String> {
        let (_, _, scope, native) = self.pieces();
        if native.is_some()
            || identity.node_uid != scope.target_node_uid
            || identity.boot_id != scope.target_boot.as_str()
            || identity.volume_uid != scope.owner.volume_uid
            || identity.operation_uid != scope.generation.initialize_operation_uid
        {
            return Err("init parent cannot change actual inherited native lineage".into());
        }
        match self {
            Self::Local(value) => value.identity = Some(identity.clone()),
            Self::Remote(value) => value.identity = Some(identity.clone()),
        }
        Ok(())
    }
    pub(super) fn approve(&mut self, request: &live::Request) -> Result<Option<bool>, String> {
        let native = self
            .pieces()
            .3
            .as_ref()
            .ok_or("init native identity not bound")?;
        let Some(kind) = native_kind(request, native) else {
            return Ok(Some(false));
        };
        let boundary = VerifiedLocalBoundary::new(request, native)?;
        let detail =
            hash(&serde_json::to_vec(request).map_err(|_| "cannot bind exact init request")?);
        self.fresh(kind, detail, &boundary)?;
        Ok(Some(true))
    }
    pub(super) fn complete(&mut self, completion: &VerifiedLocalBoundary) -> Result<(), String> {
        self.fresh(
            Boundary::InitComplete,
            completion.binding().into(),
            completion,
        )
    }
    fn fresh(
        &mut self,
        kind: Boundary,
        detail: String,
        local_boundary: &VerifiedLocalBoundary,
    ) -> Result<(), String> {
        let rt = crate::raft_node::RAFT
            .get()
            .ok_or("actual init Raft absent")?
            .rt
            .clone();
        match self {
            Self::Local(value) => rt.block_on(async {
                let owner = value
                    .owner
                    .upgrade()
                    .ok_or("actual local phase owner lost")?;
                owner.check_running(&value.scope)?;
                value.shared.check_config().await?;
                let observed =
                    core::observe_native_issuer(&value.scope.owner.volume_uid, local_boundary)
                        .await?;
                observed.require_fresh_native(local_boundary, Instant::now())?;
                let directory = value.shared.directory_for(&observed)?;
                scope_current(&value.scope, &observed, &directory)?;
                owner.check_running(&value.scope)
            }),
            Self::Remote(value) => rt.block_on(async {
                let owner = value
                    .owner
                    .upgrade()
                    .ok_or("actual remote phase owner lost")?;
                owner.check_running(&value.scope)?;
                value.shared.check_config().await?;
                let before = core::observe_local_async(&value.scope.owner.volume_uid).await?;
                let directory = value.shared.directory_for(&before)?;
                scope_current(&value.scope, &before, &directory)?;
                let request = value.session.boundary(
                    kind,
                    detail.clone(),
                    &before,
                    &directory,
                    Instant::now(),
                )?;
                let reply = match value
                    .shared
                    .call(
                        protocol::BOUNDARY_PATH,
                        &request,
                        &value.scope.issuer_node_uid,
                        &directory,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(error) => {
                        value.session.transport_lost();
                        return Err(error);
                    }
                };
                let (minimum, deadline) = value.session.boundary_wait_hint(&reply)?;
                core::wait_applied_hint(&minimum, deadline.min(owner.deadline())).await?;
                let after = core::observe_local_async(&value.scope.owner.volume_uid).await?;
                let current = value.shared.directory_for(&after)?;
                let token =
                    value
                        .session
                        .boundary_reply(reply, &after, &current, Instant::now())?;
                scope_current(&value.scope, &after, &current)?;
                owner.check_running(&value.scope)?;
                token.consume(kind, &detail)
            }),
        }
    }
}
fn native_kind(request: &live::Request, identity: &live::JobIdentity) -> Option<Boundary> {
    if request.version != 1
        || request.sequence == 0
        || &request.identity != identity
        || !valid_hash(&request.detail_sha256)
    {
        return None;
    }
    Some(match request.boundary.as_str() {
        "helper-start" if request.detail_sha256 == hash(b"native-distributed-init-phase-v4") => {
            Boundary::InitStart
        }
        "identity-check" => Boundary::InitIdentity,
        "fixed-program" => Boundary::InitProgram,
        "initialization-read" => Boundary::InitRead,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distributed_init_parent_never_grants_zeroing_cold_or_wrong_native_lineage() {
        let identity = live::JobIdentity {
            node_uid: Uid::new(),
            boot_id: "12345678-1234-4234-a234-123456789abc".into(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        };
        let mut request = live::Request {
            version: 1,
            identity: identity.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "helper-start".into(),
            detail_sha256: hash(b"native-distributed-init-phase-v4"),
        };
        assert_eq!(native_kind(&request, &identity), Some(Boundary::InitStart));
        for name in [
            "zero-write",
            "zero-fsync",
            "virgin-set-proof",
            "arbitrary-program",
            "format",
        ] {
            request.boundary = name.into();
            assert!(native_kind(&request, &identity).is_none());
        }
        request.boundary = "initialization-read".into();
        assert_eq!(native_kind(&request, &identity), Some(Boundary::InitRead));
        request.identity.attempt_uid = Uid::new();
        assert!(native_kind(&request, &identity).is_none());
    }
}
