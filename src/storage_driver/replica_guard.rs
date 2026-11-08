//! An atomic, allocation-owned nftables boundary, independent of routing and
//! connection state. Never flush a ruleset, modify a foreign table, or repair a
//! changed table implicitly. Rules survive helper exit and interface removal.
use super::{output, strings, Config, Dir, Plan, Program, Uid};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) struct Guard {
    name: String,
    objects: Vec<Value>,
}
impl Guard {
    pub(super) fn new(cfg: &Config, plan: &Plan, nonce: &Uid) -> Result<Self, String> {
        let name = format!("rks_{}_{}", plan.volume_uid.as_str(), &nonce.as_str()[..16]);
        let mut objects = vec![json!({"table":{"family":"inet","name":name}})];
        let local = plan.local(cfg)?;
        let peers = plan.peers.iter().filter(|p| p.node_uid != cfg.node_uid);
        let mut index = 0;
        for (hook, address_field, peer_field, interface_key) in [
            ("input", "daddr", "saddr", "iifname"),
            ("output", "saddr", "daddr", "oifname"),
        ] {
            objects.push(json!({"chain":{"family":"inet","table":name,"name":hook,
                "type":"filter","hook":hook,"prio":-150,"policy":"accept"}}));
            // Cover the bound local DRBD address as well as any source chosen
            // by fallback routing toward either exact planned peer. Both TCP
            // directions are covered; no established-flow accept exemption.
            let addresses = std::iter::once((address_field, local.address))
                .chain(peers.clone().map(|p| (peer_field, p.address)));
            for (field, address) in addresses {
                for port_field in ["sport", "dport"] {
                    let expr = vec![
                        json!({"match":{"op":"==","left":{"payload":{"protocol":"ip","field":field}},"right":address.to_string()}}),
                        json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":port_field}},"right":plan.port}}),
                        json!({"match":{"op":"!=","left":{"meta":{"key":interface_key}},"right":plan.interface}}),
                        json!({"counter":null}),
                        json!({"drop":null}),
                    ];
                    objects.push(
                        json!({"rule":{"family":"inet","table":name,"chain":hook,"expr":expr,
                        "comment":format!("royak-storage:{}:{index}",nonce.as_str())}}),
                    );
                    index += 1;
                }
            }
        }
        Ok(Self { name, objects })
    }
    fn read(&self) -> Result<Option<Value>, String> {
        let inventory: Value = serde_json::from_slice(&output(
            Program::Nft,
            &strings(&["--json", "list", "tables"]),
        )?)
        .map_err(|_| "invalid nftables table inventory")?;
        let tables = inventory["nftables"]
            .as_array()
            .ok_or("missing nftables table inventory")?;
        let count = tables
            .iter()
            .filter(|v| v["table"]["family"] == "inet" && v["table"]["name"] == self.name)
            .count();
        if count > 1 {
            return Err("ambiguous storage transport guard".into());
        }
        if count == 0 {
            return Ok(None);
        }
        let actual: Value = serde_json::from_slice(&output(
            Program::Nft,
            &strings(&["--json", "list", "table", "inet", &self.name]),
        )?)
        .map_err(|_| "invalid storage transport guard inventory")?;
        Ok(Some(actual))
    }
    fn validate(&self, actual: &Value) -> Result<(), String> {
        let expected = json!({"nftables":self.objects});
        if normalized(actual)? != normalized(&expected)? {
            return Err("storage transport guard changed or is not allocation-owned; never adopt, overwrite or remove it".into());
        }
        Ok(())
    }
    pub(super) fn verify(&self) -> Result<String, String> {
        self.validate(
            &self
                .read()?
                .ok_or("active replica has no encrypted-only transport guard")?,
        )?;
        Ok(self.name.clone())
    }
    pub(super) fn ensure(&self, cfg: &Config, dir: &Dir) -> Result<(), String> {
        if let Some(actual) = self.read()? {
            return self.validate(&actual);
        }
        let commands: Vec<Value> = self
            .objects
            .iter()
            .enumerate()
            .map(|(i, obj)| {
                // `create`, unlike `add`, refuses an unexpected table that appears
                // in the read/create gap. The whole batch is one kernel transaction.
                if i == 0 {
                    json!({"create":obj})
                } else {
                    json!({"add":obj})
                }
            })
            .collect();
        let file = format!("{}.json", self.name);
        dir.write(
            &file,
            &serde_json::to_vec(&json!({"nftables":commands}))
                .map_err(|_| "cannot encode transport guard")?,
        )?;
        output(
            Program::Nft,
            &strings(&[
                "--json",
                "--file",
                cfg.journal_path()
                    .join(file)
                    .to_str()
                    .ok_or("invalid guard path")?,
            ]),
        )?;
        self.verify().map(|_| ())
    }
    pub(super) fn remove(&self) -> Result<(), String> {
        let Some(actual) = self.read()? else {
            return Ok(());
        };
        self.validate(&actual)?;
        output(
            Program::Nft,
            &strings(&["delete", "table", "inet", &self.name]),
        )?;
        if self.read()?.is_some() {
            return Err("transport guard removal outcome UNKNOWN".into());
        }
        Ok(())
    }
}

// Ignore only kernel-assigned handles and live counters. Chain configuration,
// rule order within each chain, expressions, verdicts, comments, extra objects
// and flags all remain authoritative; a permissive/foreign table is refused.
fn normalized(value: &Value) -> Result<Value, String> {
    let mut table = None;
    let mut chains = BTreeMap::new();
    let mut rules: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for entry in value["nftables"]
        .as_array()
        .ok_or("missing guard objects")?
    {
        let object = entry
            .as_object()
            .filter(|o| o.len() == 1)
            .ok_or("ambiguous guard object")?;
        let (kind, data) = object.iter().next().ok_or("empty guard object")?;
        if kind == "metainfo" {
            continue;
        }
        let mut data = data.as_object().cloned().ok_or("invalid guard object")?;
        data.remove("handle");
        match kind.as_str() {
            "table" => {
                if table.replace(Value::Object(data)).is_some() {
                    return Err("duplicate guard table".into());
                }
            }
            "chain" => {
                let name = data
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("missing guard chain name")?
                    .to_string();
                if chains.insert(name, Value::Object(data)).is_some() {
                    return Err("duplicate guard chain".into());
                }
            }
            "rule" => {
                let chain = data
                    .get("chain")
                    .and_then(Value::as_str)
                    .ok_or("missing guard rule chain")?
                    .to_string();
                for expr in data
                    .get_mut("expr")
                    .and_then(Value::as_array_mut)
                    .ok_or("missing guard expressions")?
                {
                    if let Some(counter) = expr.get_mut("counter") {
                        if !counter.is_null()
                            && (counter.as_object().is_none_or(|o| o.len() != 2)
                                || counter["packets"].as_u64().is_none()
                                || counter["bytes"].as_u64().is_none())
                        {
                            return Err("invalid guard counter".into());
                        }
                        *counter = Value::Null;
                    }
                }
                rules.entry(chain).or_default().push(Value::Object(data));
            }
            _ => return Err("unplanned object in storage guard; never adopt it".into()),
        }
    }
    Ok(json!({"table":table.ok_or("missing guard table")?,"chains":chains,"rules":rules}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> Guard {
        let cfg = super::super::super::test_config();
        let plan = Plan {
            version: 1,
            cluster_id: cfg.cluster_id.clone(),
            pool_uid: cfg.pool_uid.clone(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            minor: 512,
            port: 27791,
            interface: "rkstore1".into(),
            shared_secret: "a".repeat(48),
            peers: std::array::from_fn(|i| super::super::Peer {
                node_uid: if i == 0 {
                    cfg.node_uid.clone()
                } else {
                    Uid::new()
                },
                node_id: i as u8,
                hostname: format!("node-{i}"),
                address: std::net::Ipv4Addr::new(10, 246, 75, i as u8 + 1),
                public_key: format!("{}=", ((b'A' + i as u8) as char).to_string().repeat(43)),
                vg_name: cfg.vg_name.clone(),
            }),
        };
        Guard::new(&cfg, &plan, &Uid::new()).unwrap()
    }
    #[test]
    fn guard_is_exact_ordered_allocation_owned_and_counters_are_not_policy() {
        let g = spec();
        let expected = json!({"nftables":g.objects});
        g.validate(&expected).unwrap();
        let mut actual = expected.clone();
        for obj in actual["nftables"].as_array_mut().unwrap() {
            if let Some(rule) = obj.get_mut("rule") {
                rule["handle"] = 17.into();
                rule["expr"][3]["counter"] = json!({"packets":9,"bytes":500});
            }
        }
        g.validate(&actual).unwrap();
        for case in 0..8 {
            let mut bad = actual.clone();
            let rules = bad["nftables"].as_array_mut().unwrap();
            match case {
                0 => rules[2]["rule"]["expr"][4] = json!({"accept":null}),
                1 => rules[2]["rule"]["expr"][2]["match"]["op"] = "==".into(),
                2 => rules[2]["rule"]["comment"] = "foreign".into(),
                3 => rules[1]["chain"]["prio"] = 0.into(),
                4 => {
                    rules.remove(2);
                }
                5 => rules.swap(2, 3),
                6 => rules.push(json!({"set":{"name":"foreign"}})),
                _ => rules[0]["table"]["flags"] = json!(["dormant"]),
            }
            assert!(g.validate(&bad).is_err(), "case {case}");
        }
        let other = spec();
        assert!(other.validate(&actual).is_err());
        assert_eq!(
            g.objects.iter().filter(|o| o.get("rule").is_some()).count(),
            12
        );
    }
}
