//! Opt-in ingress-only laboratory. Never starts reconciliation, Docker, chaos,
//! the control-plane API or a state writer. The normal test run skips it.
use super::*;
use std::path::Path;
use tokio::io::AsyncWriteExt;

fn routes(path: &Path) -> Vec<ResolvedRoute> {
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= 262144);
    let config: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rows = config["routes"].as_array().unwrap();
    assert!(rows.len() <= 16);
    rows.iter().map(|row| {
        let host = row["host"].as_str().unwrap().to_string();
        let path = row["path"].as_str().unwrap().to_string();
        assert!(path.starts_with('/'));
        let entries = row["backends"].as_array().unwrap();
        assert!(entries.len() <= 64);
        let backends = entries.iter().map(|entry| {
            let ip: std::net::IpAddr = entry[0].as_str().unwrap().parse().unwrap();
            let private = match ip {
                std::net::IpAddr::V4(v) => v.is_loopback() || v.is_private(),
                std::net::IpAddr::V6(v) => v.is_loopback() || v.is_unique_local(),
            };
            assert!(private, "Laboratory targets must be private or loopback");
            let port = u16::try_from(entry[1].as_u64().unwrap()).unwrap();
            assert!(port > 0);
            (ip.to_string(), port, String::new(), port)
        }).collect();
        ResolvedRoute { host, path, backends }
    }).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit private finite qualification; no control-plane or Docker access"]
async fn ingress_only_laboratory() {
    let config_path = std::env::var("ROYAK_INGRESS_LAB_CONFIG").unwrap();
    let path = Path::new(&config_path);
    let config: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let address: std::net::SocketAddr = config["listen"].as_str().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let seconds = config["duration_seconds"].as_u64().unwrap();
    assert!((1..=600).contains(&seconds));
    *ingress_snapshot().lock().unwrap() = Arc::new(routes(path));
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let actual = listener.local_addr().unwrap();
    let ready = path.with_extension("ready.json");
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(ready).unwrap();
    use std::io::Write;
    file.write_all(serde_json::json!({"pid": std::process::id(), "listen": actual.to_string(),
        "control_plane_started": false, "state_writer_started": false, "docker_access": false}).to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
    let world = Arc::new(RwLock::new(DesiredWorld::new()));
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(seconds));
    tokio::pin!(deadline);
    let mut refresh = tokio::time::interval(std::time::Duration::from_millis(100));
    let mut tasks = tokio::task::JoinSet::new();
    let capacity = Arc::new(tokio::sync::Semaphore::new(256));
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            _ = refresh.tick() => {
                *ingress_snapshot().lock().unwrap() = Arc::new(routes(path));
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.unwrap();
                stream.set_nodelay(true).unwrap();
                let Ok(permit) = capacity.clone().try_acquire_owned() else {
                    let _ = stream.shutdown().await;
                    continue;
                };
                let world = world.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let service = hyper::service::service_fn(move |request| handle_ingress(request, world.clone()));
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
