//! Laptop client: no Docker, local state, insecure TLS switch or public bind.
use clap::{Args, Subcommand};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Args, Clone)]
pub struct Client {
    #[arg(long)]
    pub server: String,
    #[arg(long)]
    pub ca_cert: PathBuf,
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub namespace: String,
}
#[derive(Subcommand)]
pub enum Action {
    Open {
        #[command(flatten)]
        client: Client,
        #[arg(long)]
        service: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "0")]
        local_port: u16,
        #[arg(long, default_value = "300")]
        ttl_seconds: u64,
    },
    List {
        #[command(flatten)]
        client: Client,
    },
    Revoke {
        #[command(flatten)]
        client: Client,
        id: String,
    },
    Audit {
        #[command(flatten)]
        client: Client,
    },
}
#[derive(Clone)]
struct Connection {
    host: String,
    port: u16,
    authority: String,
    config: Arc<rustls::ClientConfig>,
    token: String,
    namespace: String,
}
impl Connection {
    fn new(c: &Client) -> Result<Self, String> {
        let uri: hyper::Uri = c.server.parse().map_err(|_| "invalid HTTPS server")?;
        if uri.scheme_str() != Some("https")
            || uri
                .authority()
                .map(|a| a.as_str().contains('@'))
                .unwrap_or(false)
            || uri
                .path_and_query()
                .map(|p| p.as_str() != "/")
                .unwrap_or(false)
        {
            return Err("Connect server must be an HTTPS origin without path/query".into());
        }
        let host = uri.host().ok_or("server host missing")?.to_string();
        let port = uri.port_u16().unwrap_or(443);
        if !crate::store::is_dns_label(&c.namespace) {
            return Err("explicit namespace required".into());
        }
        let token = if let Some(path) = &c.token_file {
            use std::io::Read;
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let mut file = options
                .open(path)
                .map_err(|_| "private token file unavailable")?;
            let meta = file.metadata().map_err(|_| "token file unavailable")?;
            if !meta.is_file() {
                return Err("token must be a regular private file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err("token file must have mode 0600".into());
                }
            }
            if meta.len() > 8192 {
                return Err("token file too large".into());
            }
            let mut value = String::new();
            file.read_to_string(&mut value)
                .map_err(|_| "token file unavailable")?;
            value
        } else {
            std::env::var("ROYAK_TOKEN").map_err(|_| "provide --token-file or ROYAK_TOKEN")?
        };
        let token = token.trim().to_string();
        if token.len() < 16 || token.contains(['\r', '\n']) {
            return Err("invalid bearer token".into());
        }
        let pem = std::fs::read(&c.ca_cert).map_err(|_| "trusted CA certificate unavailable")?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            roots
                .add(cert.map_err(|_| "invalid CA PEM")?)
                .map_err(|_| "invalid CA certificate")?;
        }
        if roots.is_empty() {
            return Err("trusted CA file is empty".into());
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            host,
            port,
            authority: uri
                .authority()
                .ok_or("server authority missing")?
                .to_string(),
            config: Arc::new(config),
            token,
            namespace: c.namespace.clone(),
        })
    }
    fn path(&self) -> String {
        format!("/royak/v1/connect/namespaces/{}/sessions", self.namespace)
    }
    async fn socket(
        &self,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
        let tcp = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        .map_err(|_| "server connection timed out")?
        .map_err(|_| "server unreachable")?;
        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| "invalid TLS server name")?;
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio_rustls::TlsConnector::from(self.config.clone()).connect(name, tcp),
        )
        .await
        .map_err(|_| "TLS timeout")?
        .map_err(|_| {
            "TLS verification failed; use the trusted certificate for this server".to_string()
        })
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let socket = self.socket().await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
                .await
                .map_err(|_| "HTTPS handshake failed")?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let data = body.map(|v| v.to_string()).unwrap_or_default();
        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", &self.authority)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(data)))
            .map_err(|_| "invalid request")?;
        let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(req))
            .await
            .map_err(|_| "Connect request timeout")?
            .map_err(|_| "Connect request failed")?;
        let status = response.status();
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            http_body_util::Limited::new(response.into_body(), 1024 * 1024).collect(),
        )
        .await
        .map_err(|_| "Connect response timeout")?
        .map_err(|_| "invalid bounded response")?
        .to_bytes();
        let result: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid Connect response")?;
        if !status.is_success() {
            return Err(format!(
                "Connect HTTP {}: {}",
                status.as_u16(),
                result["error"].as_str().unwrap_or("request refused")
            ));
        }
        Ok(result)
    }
    async fn forward(&self, id: &str, mut local: tokio::net::TcpStream) -> Result<(), String> {
        let mut socket = self.socket().await?;
        let request=format!("GET {}/{id}/stream HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: Upgrade\r\nUpgrade: royak-connect-v1\r\n\r\n",self.path(),self.authority,self.token);
        tokio::time::timeout(Duration::from_secs(6), async {
            socket
                .write_all(request.as_bytes())
                .await
                .map_err(|_| "upgrade write failed")?;
            socket.flush().await.map_err(|_| "upgrade flush failed")
        })
        .await
        .map_err(|_| "upgrade write timeout")??;
        // Byte-at-a-time bounded head avoids consuming any backend TCP bytes.
        let mut head = Vec::new();
        let mut byte = [0];
        tokio::time::timeout(Duration::from_secs(6), async {
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() >= 8192 {
                    return Err("upgrade headers too large");
                }
                if socket
                    .read(&mut byte)
                    .await
                    .map_err(|_| "upgrade read failed")?
                    == 0
                {
                    return Err("upgrade closed");
                }
                head.push(byte[0]);
            }
            Ok(())
        })
        .await
        .map_err(|_| "upgrade timeout")??;
        if !head.starts_with(b"HTTP/1.1 101 ") {
            return Err("Connect stream refused; check session/rights/Ready backends".into());
        }
        tokio::io::copy_bidirectional(&mut local, &mut socket)
            .await
            .map_err(|_| "Connect stream closed")?;
        Ok(())
    }
}
pub async fn run(action: &Action) -> Result<(), String> {
    let client = match action {
        Action::Open { client, .. }
        | Action::List { client }
        | Action::Revoke { client, .. }
        | Action::Audit { client } => client,
    };
    let c = Connection::new(client)?;
    match action {
        Action::List { .. } => println!("{}", c.request("GET", &c.path(), None).await?),
        Action::Audit { .. } => println!(
            "{}",
            c.request(
                "GET",
                &format!("/royak/v1/connect/namespaces/{}/audit", c.namespace),
                None
            )
            .await?
        ),
        Action::Revoke { id, .. } => {
            if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid session id".into());
            }
            println!(
                "{}",
                c.request("DELETE", &format!("{}/{id}", c.path()), None)
                    .await?
            );
        }
        Action::Open {
            service,
            port,
            local_port,
            ttl_seconds,
            ..
        } => {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", *local_port))
                .await
                .map_err(|_| "cannot bind requested loopback port")?;
            let session = c
                .request(
                    "POST",
                    &c.path(),
                    Some(json!({"service":service,"port":port,"ttl_seconds":ttl_seconds})),
                )
                .await?;
            let id = session["id"]
                .as_str()
                .ok_or("session id missing")?
                .to_string();
            println!(
                "{}",
                json!({"session":id,"local_address":listener.local_addr().map_err(|e|e.to_string())?.to_string(),"namespace":c.namespace,"service":service,"port":port,"expires_at":session["expires_at"]})
            );
            let mut tasks = tokio::task::JoinSet::new();
            let mut poll = tokio::time::interval(Duration::from_millis(250));
            let mut ended = Box::pin(tokio::signal::ctrl_c());
            loop {
                tokio::select! {
                    _=&mut ended=>break,
                    _=poll.tick()=>{match c.request("GET",&format!("{}/{id}",c.path()),None).await {Ok(s) if s["closed"]==false=>{},_=>break}},
                    result=listener.accept()=>{let (stream,_)=result.map_err(|_|"local accept failed")?;if tasks.len()>=8{drop(stream);continue;}let c=c.clone();let id=id.clone();tasks.spawn(async move{if let Err(error)=c.forward(&id,stream).await { eprintln!("Connect forwarding stopped: {error}"); }});},
                    _=tasks.join_next(),if !tasks.is_empty()=>{}
                }
            }
            tasks.abort_all();
            drop(listener);
            let _ = c
                .request("DELETE", &format!("{}/{id}", c.path()), None)
                .await;
            println!("Connect session closed; loopback listener removed");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_plaintext_before_reading_credentials() {
        let c = Client {
            server: "http://localhost:6443".into(),
            ca_cert: PathBuf::new(),
            token_file: None,
            namespace: "team".into(),
        };
        assert!(Connection::new(&c).err().unwrap().contains("HTTPS"));
    }
}
