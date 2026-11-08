//! Local Linux root-Docker adapter. Unsupported/proxied/unverifiable identity
//! fails closed; there is no environment-variable bypass in production.
use super::*;

fn json(response: wire::Response, expected: u16) -> Result<serde_json::Value, String> {
    if response.status != expected {
        return Err(format!(
            "Docker HTTP {} instead of {expected}",
            response.status
        ));
    }
    serde_json::from_slice(&response.body).map_err(|e| format!("invalid Docker JSON: {e}"))
}
fn typed<T: serde::de::DeserializeOwned>(
    response: wire::Response,
    expected: u16,
) -> Result<T, String> {
    if response.status != expected {
        return Err(format!(
            "Docker HTTP {} instead of {expected}",
            response.status
        ));
    }
    serde_json::from_slice(&response.body)
        .map_err(|e| format!("invalid or duplicate Docker authority fields: {e}"))
}
#[derive(Deserialize)]
struct ContainerFields {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "ExecIDs")]
    execs: serde_json::Value,
    #[serde(rename="Config",default)]
    config:Option<serde_json::Value>,
}
#[derive(Deserialize)]
struct ExecFields {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ContainerID")]
    container: String,
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "ExitCode")]
    exit: serde_json::Value,
}
#[derive(Deserialize)]
struct CreateFields {
    #[serde(rename = "Id")]
    id: String,
}
fn parse_container(response: wire::Response) -> Result<Container, String> {
    if response.status == 404 {
        return Ok(Container::Absent);
    }
    let fields: ContainerFields = typed(response, 200)?;
    let id = fields.id;
    if !hex(&id, 64) {
        return Err("invalid full container ID".into());
    }
    if crate::docker::managed::registered_target(&id){
        return Err("native managed target cannot enter legacy exec/probe admission".into());
    }
    match fields.config.as_ref().and_then(|config|config.get("Labels")){
        Some(labels)=>if crate::docker::managed::native_labels(labels)?{
            return Err("native managed diagnostics need their own current consumer authority; legacy admission UNKNOWN".into());
        },
        None if crate::docker::managed::strict_scope()=>
            return Err("native-history diagnostic inspect lacks exact labels; UNKNOWN".into()),
        None=>(),
    }
    let execs = match &fields.execs {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::Array(values) if values.len() <= PER_CONTAINER => {
            let mut seen = BTreeSet::new();
            let mut out = Vec::new();
            for v in values {
                let id = v
                    .as_str()
                    .filter(|s| hex(s, 64))
                    .ok_or("invalid ExecIDs entry")?;
                if !seen.insert(id) {
                    return Err("duplicate ExecIDs entry".into());
                }
                out.push(id.to_string());
            }
            out
        }
        _ => return Err("missing/wrong/oversized Docker ExecIDs census".into()),
    };
    Ok(Container::Present { id, execs })
}
fn parse_exec(response: wire::Response, expected: &str) -> Result<Exec, String> {
    if response.status == 404 {
        return Ok(Exec::Absent);
    }
    let fields: ExecFields = typed(response, 200)?;
    let id = fields.id;
    if id != expected || !hex(&id, 64) {
        return Err("invalid full exec ID association".into());
    }
    let container = fields.container;
    if !hex(&container, 64) {
        return Err("invalid full exec container association".into());
    }
    let running = fields.running;
    let exit = match fields.exit {
        serde_json::Value::Null => None,
        v => Some(v.as_i64().ok_or("invalid numeric exec exit code")?),
    };
    Ok(Exec::Present {
        id,
        container,
        running,
        exit,
    })
}

use super::credentials::AdmittedStream;
#[cfg(target_os = "linux")]
use super::credentials::{current_boot as boot, process_start as start_ticks};

pub(super) struct Docker {
    socket: String,
    binding: Binding,
    deadline: Instant,
}
pub(super) fn recovery_open(deadline: Instant) -> Result<Docker, String> {
    Docker::open(deadline)
}
impl Docker {
    fn open(deadline: Instant) -> Result<Self, String> {
        if std::env::var("DOCKER_HOST")
            .ok()
            .is_some_and(|host| !host.starts_with("unix://"))
        {
            return Err("durable exec admission supports only an explicit local Unix daemon; no TCP/default fallback".into());
        }
        let socket = crate::docker::docker_sock();
        let stream = AdmittedStream::connect(&socket, None, deadline)?;
        let binding = stream.binding()?.clone();
        stream.validate()?;
        Ok(Self {
            socket,
            binding,
            deadline,
        })
    }
    fn connect(&self) -> Result<AdmittedStream, String> {
        AdmittedStream::connect(&self.socket, Some(&self.binding), self.deadline)
    }
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        bound: usize,
    ) -> Result<wire::Response, String> {
        let mut stream = self.connect()?;
        let response = wire::request(&mut stream, method, path, body, bound, self.deadline)?;
        stream.validate()?;
        Ok(response)
    }
    fn registered(
        &self,
        r: &crate::exec_process::Reference,
    ) -> Result<Option<serde_json::Value>, String> {
        let response = self.request("GET", &format!("/exec/{}/json", r.id), None, wire::JSON)?;
        match parse_exec(response.clone(), &r.id)? {
            Exec::Absent => {
                // This double404 is only a foreground-cleanup witness. It is
                // deliberately NOT used by metadata charge reclamation.
                match parse_container(self.request("GET",&format!("/containers/{}/json",r.container),None,wire::JSON)?)? {
                    Container::Absent=>Ok(None),
                    _=>Err("registered exec404 with live container is not foreground termination proof".into()),
                }
            }
            Exec::Present { container, .. } if container == r.container => {
                Ok(Some(json(response, 200)?))
            }
            _ => Err("fresh attested foreground exec association differs".into()),
        }
    }
}
impl Engine for Docker {
    fn binding(&mut self) -> Result<Binding, String> {
        self.connect()?;
        Ok(self.binding.clone())
    }
    fn container(&mut self, id: &str) -> Result<Container, String> {
        if !hex(id, id.len()) || !(12..=64).contains(&id.len()) {
            return Err("invalid container inspect target".into());
        }
        parse_container(self.request("GET", &format!("/containers/{id}/json"), None, wire::JSON)?)
    }
    fn exec(&mut self, id: &str) -> Result<Exec, String> {
        if !hex(id, 64) {
            return Err("invalid exec inspect target".into());
        }
        parse_exec(
            self.request("GET", &format!("/exec/{id}/json"), None, wire::JSON)?,
            id,
        )
    }
    fn create(&mut self, cid: &str, body: &serde_json::Value) -> Result<String, CreateFailure> {
        let raw =
            serde_json::to_vec(body).map_err(|e| CreateFailure::NotSubmitted(e.to_string()))?;
        // This same connection is sender-attested BEFORE any Create bytes.
        let mut stream = self.connect().map_err(CreateFailure::NotSubmitted)?;
        let response = wire::request(
            &mut stream,
            "POST",
            &format!("/containers/{cid}/exec"),
            Some(&raw),
            wire::JSON,
            self.deadline,
        )
        .map_err(CreateFailure::Ambiguous)?;
        stream.validate().map_err(CreateFailure::Ambiguous)?;
        let receipt: CreateFields = typed(response, 201).map_err(CreateFailure::Ambiguous)?;
        if !hex(&receipt.id, 64) {
            return Err(CreateFailure::Ambiguous(
                "Create receipt lacks full exec ID".into(),
            ));
        }
        Ok(receipt.id)
    }
    fn owner_alive(&mut self, owner: &Owner) -> Result<bool, String> {
        #[cfg(target_os = "linux")]
        {
            if owner.boot != boot()? {
                return Err("owner/node boot identity changed".into());
            }
            match std::fs::metadata(format!("/proc/{}", owner.pid)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e.to_string()),
                Ok(_) => Ok(start_ticks(owner.pid)? == owner.start),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = owner;
            Err("process identity requires Linux".into())
        }
    }
}

#[derive(Deserialize)]
struct CensusFields {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Labels")]
    labels: CensusLabels,
}
struct CensusLabels(Option<std::collections::BTreeMap<String, String>>);
impl<'de> Deserialize<'de> for CensusLabels {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Labels;
        impl<'de> serde::de::Visitor<'de> for Labels {
            type Value = CensusLabels;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an explicit null or bounded unique string-label object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(CensusLabels(None))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut labels = std::collections::BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if labels.len() >= 128 || labels.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom(
                            "duplicate/oversized ownership labels",
                        ));
                    }
                }
                Ok(CensusLabels(Some(labels)))
            }
        }
        deserializer.deserialize_any(Labels)
    }
}
impl super::recovery::RecoveryEngine for Docker {
    fn owned_census(
        &mut self,
        cluster: &str,
        node: &str,
    ) -> Result<Vec<super::recovery::Census>, String> {
        // All=1 with NO limit/pagination guess: a capped/partial list is not a
        // completed empty census. Framing and total response bytes stay bounded.
        let rows: Vec<CensusFields> = typed(
            self.request("GET", "/containers/json?all=1", None, wire::JSON)?,
            200,
        )?;
        if rows.len() > CONTAINERS {
            return Err("actual daemon container census exceeds fixed recovery bound".into());
        }
        let mut seen = BTreeSet::new();
        let mut result = Vec::new();
        let mut total = 0usize;
        for row in rows {
            if !hex(&row.id, 64) || !seen.insert(row.id.clone()) {
                return Err("invalid/duplicate actual container ownership census".into());
            }
            let Some(labels) = row.labels.0 else {
                continue;
            }; // explicit foreign unlabelled container
            if labels.get(crate::store::LABEL_CLUSTER).map(String::as_str) != Some(cluster)
                || labels.get(crate::store::LABEL_NODE).map(String::as_str) != Some(node)
            {
                continue;
            } // unrelated resources are never inspected/signalled
            let Container::Present { id, execs } = self.container(&row.id)? else {
                return Err(
                    "owned container changed during full recovery census; no partial success"
                        .into(),
                );
            };
            if id != row.id {
                return Err("recovery full container association changed".into());
            }
            total = total
                .checked_add(execs.len())
                .filter(|n| *n <= NODE_RECORDS)
                .ok_or("aggregate actual recovery ExecIDs exceed fixed bound")?;
            result.push(super::recovery::Census { id, execs });
        }
        Ok(result)
    }
    fn drain(
        &mut self,
        reference: &crate::exec_process::Reference,
    ) -> Result<Option<crate::exec_process::RecoveryOsDrained>, String> {
        crate::exec_process::recovery_drain(reference, &mut |r| self.registered(r))
    }
}

pub(crate) struct Receipt {
    created: Created,
    socket: String,
    reserved: bool,
    submitted: bool,
}
impl Receipt {
    pub(crate) fn container(&self) -> &str {
        &self.created.container
    }
    pub(crate) fn id(&self) -> &str {
        &self.created.id
    }
    pub(crate) fn nonce(&self) -> &str {
        &self.created.nonce
    }
    pub(crate) fn connect_start(&self) -> Result<AdmittedStream, String> {
        Docker {
            socket: self.socket.clone(),
            binding: self.created.binding.clone(),
            deadline: Instant::now() + Duration::from_secs(30),
        }
        .connect()
        .map_err(unknown)
    }
    pub(crate) fn before_start(&mut self) -> Result<(), String> {
        // Recheck actual Start peer before the durable transition. Caller uses
        // connect_start for the actual side-effecting socket as well.
        self.connect_start()?;
        transition(
            Path::new(ROOT),
            &self.created,
            Phase::StartUnknown,
            Instant::now() + Duration::from_secs(30),
        )?;
        self.reserved = true;
        Ok(())
    }
    pub(crate) fn submit_start(&mut self) -> Result<(), String> {
        if !self.reserved || self.submitted {
            return Err(unknown("Start submission is not one-shot"));
        }
        // Set BEFORE the first transport write. Any write error/partial write
        // retains unknown-start lineage, never a fabricated no-post witness.
        self.submitted = true;
        Ok(())
    }
    pub(crate) fn request_start(&mut self, body: &[u8], bound: usize) -> Result<Vec<u8>, String> {
        let detached = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("Detach").and_then(|v| v.as_bool()))
            .ok_or_else(|| unknown("invalid Start detach mode"))?;
        let mut stream = self.connect_start()?;
        self.before_start()?;
        self.submit_start()?;
        let path = format!("/exec/{}/start", self.id());
        let deadline = Instant::now() + Duration::from_secs(30);
        let result = if detached {
            wire::request(&mut stream, "POST", &path, Some(body), bound, deadline)
        } else {
            wire::request_raw_start(&mut stream, &path, body, bound, deadline)
        }
        .map_err(unknown)?;
        stream.validate().map_err(unknown)?;
        // Docker Start400 can carry the executable-not-found outcome. Callers
        // still require the later numeric ExecInspect result (126/127); this
        // is not a positive completion receipt and releases no metadata charge.
        if !(200..300).contains(&result.status)
            && result.status != 400
            && !(result.status == 101 && !detached)
        {
            return Err(format!(
                "Docker Start HTTP {} (durable capacity retained)",
                result.status
            ));
        }
        Ok(result.body)
    }
}
impl Drop for Receipt {
    fn drop(&mut self) {
        if !self.submitted {
            let _ = abort_before_post(
                Path::new(ROOT),
                &self.created,
                Instant::now() + Duration::from_secs(30),
            );
        }
    }
}

pub(crate) fn create(
    id: &str,
    nonce: &str,
    body: &serde_json::Value,
    cancelled: &dyn Fn() -> Result<(), String>,
) -> Result<Receipt, String> {
    super::recovery::allow_create(id)?; // pure fast gate; never initializes/scans here
    if serde_json::to_vec(body).map_err(unknown)?.len() > wire::JSON {
        return Err(unknown(
            "owned exec request exceeds the bounded Docker body",
        ));
    }
    let marker = format!("ROYAK_EXEC_SESSION={nonce}");
    if body
        .get("Env")
        .and_then(|v| v.as_array())
        .is_none_or(|values| values.len() != 1 || values[0].as_str() != Some(marker.as_str()))
        || body
            .get("Cmd")
            .and_then(|v| v.as_array())
            .is_none_or(|values| values.is_empty() || values.iter().any(|v| !v.is_string()))
    {
        return Err(unknown(
            "owned exec body lacks exact injected nonce/command",
        ));
    }
    cancelled()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut engine = Docker::open(deadline).map_err(unknown)?;
    #[cfg(target_os = "linux")]
    let owner = Owner {
        boot: engine.binding.boot.clone(),
        pid: std::process::id(),
        start: start_ticks(std::process::id()).map_err(unknown)?,
    };
    #[cfg(not(target_os = "linux"))]
    return Err(unknown("node owner identity requires Linux"));
    #[cfg(target_os = "linux")]
    {
        let created = create_inner(
            Path::new(ROOT),
            &mut engine,
            owner,
            id,
            nonce,
            body,
            deadline,
            cancelled,
        )?;
        Ok(Receipt {
            created,
            socket: engine.socket,
            reserved: false,
            submitted: false,
        })
    }
}

pub(crate) fn probe_container(id: &str) -> Result<serde_json::Value, String> {
    super::recovery::allow_create(id)?; // refusal stays typed infrastructure-unknown
    if !(12..=64).contains(&id.len()) || !hex(id, id.len()) {
        return Err(unknown("invalid probe container identity"));
    }
    let engine = Docker::open(Instant::now() + Duration::from_secs(30)).map_err(unknown)?;
    let response = engine
        .request("GET", &format!("/containers/{id}/json"), None, wire::JSON)
        .map_err(unknown)?;
    let parsed = parse_container(response.clone()).map_err(unknown)?;
    let value = json(response, 200).map_err(unknown)?;
    if !matches!(parsed,Container::Present {id:full,..} if full.starts_with(id)) {
        return Err(unknown("probe container prefix retargeted"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_ownership_labels_require_explicit_unique_bounded_strings() {
        let id = "a".repeat(64);
        for raw in [
            format!(r#"{{"Id":"{id}","Labels":null}}"#),
            format!(
                r#"{{"Id":"{id}","Labels":{{"royak.cluster":"aabbccddeeff","royak.node":"fixture"}}}}"#
            ),
        ] {
            assert!(serde_json::from_str::<CensusFields>(&raw).is_ok());
        }
        for raw in [
            format!(r#"{{"Id":"{id}"}}"#),
            format!(r#"{{"Id":"{id}","Labels":false}}"#),
            format!(r#"{{"Id":"{id}","Labels":{{"royak.node":null}}}}"#),
            format!(r#"{{"Id":"{id}","Labels":{{"royak.node":"other","royak.node":"fixture"}}}}"#),
            format!(r#"{{"Id":"{id}","Labels":null,"Labels":{{}}}}"#),
        ] {
            assert!(serde_json::from_str::<CensusFields>(&raw).is_err(), "{raw}");
        }
        let labels = (0..129)
            .map(|n| (n.to_string(), "v"))
            .collect::<std::collections::BTreeMap<_, _>>();
        let raw = serde_json::json!({"Id":id,"Labels":labels}).to_string();
        assert!(serde_json::from_str::<CensusFields>(&raw).is_err());
    }
    fn response(value: serde_json::Value) -> wire::Response {
        wire::Response {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
        }
    }
    #[test]
    fn actual_census_null_is_empty_but_missing_wrong_duplicate_and_oversize_are_unknown() {
        let cid = "a".repeat(64);
        assert!(
            matches!(parse_container(response(serde_json::json!({"Id":cid,"ExecIDs":null}))).unwrap(),Container::Present {execs,..} if execs.is_empty())
        );
        for v in [
            serde_json::json!({"Id":cid}),
            serde_json::json!({"Id":cid,"ExecIDs":false}),
            serde_json::json!({"Id":cid,"ExecIDs":["short"]}),
            serde_json::json!({"Id":cid,"ExecIDs":["b".repeat(64),"b".repeat(64)]}),
            serde_json::json!({"Id":cid,"ExecIDs":vec!["b".repeat(64);PER_CONTAINER+1]}),
        ] {
            assert!(parse_container(response(v)).is_err());
        }
    }
    #[test]
    fn inspect_requires_explicit_full_association_running_and_exit_fields_not_env() {
        let id = "b".repeat(64);
        let cid = "a".repeat(64);
        assert!(parse_exec(
            response(
                serde_json::json!({"ID":id,"ContainerID":cid,"Running":false,"ExitCode":null})
            ),
            &id
        )
        .is_ok());
        for v in [
            serde_json::json!({"ID":id,"ContainerID":cid,"Running":false}),
            serde_json::json!({"ID":id,"ContainerID":cid,"Running":"false","ExitCode":null}),
            serde_json::json!({"Id":id,"ContainerID":cid,"Running":false,"ExitCode":null}),
            serde_json::json!({"ID":id,"ContainerID":"short","Running":false,"ExitCode":null}),
        ] {
            assert!(parse_exec(response(v), &id).is_err());
        }
    }
    #[test]
    fn duplicate_authority_fields_are_not_valid_create_or_observation_receipts() {
        let id = "b".repeat(64);
        let cid = "a".repeat(64);
        let raw = format!(r#"{{"Id":"{id}","Id":"{id}"}}"#);
        assert!(typed::<CreateFields>(
            wire::Response {
                status: 201,
                body: raw.into_bytes()
            },
            201
        )
        .is_err());
        let raw = format!(r#"{{"Id":"{cid}","ExecIDs":null,"ExecIDs":[]}}"#);
        assert!(parse_container(wire::Response {
            status: 200,
            body: raw.into_bytes()
        })
        .is_err());
        let raw = format!(
            r#"{{"ID":"{id}","ContainerID":"{cid}","Running":false,"Running":true,"ExitCode":null}}"#
        );
        assert!(parse_exec(
            wire::Response {
                status: 200,
                body: raw.into_bytes()
            },
            &id
        )
        .is_err());
    }
}
