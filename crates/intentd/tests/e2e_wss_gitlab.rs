//! Native GitLab settings and forge requests through real authenticated WSS.
//! A loopback HTTP fixture replaces only the external GitLab API; the registry,
//! secret store, provider selection, router, services and TLS transport are real.
#![cfg(unix)]
mod common;
use futures_util::{SinkExt, StreamExt};
use intent_core::{Result as CoreResult, WorkspaceApi};
use intent_services::{EventBus, InMemorySecretStore, Services, SettingsRegistry};
use intent_store::Store;
use intent_transport::{
    ensure_tls_certificate, AsyncTokenStore, TokenStore, WsApiServer, WsOptions,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
const PAT: &str = "gitlab-hermetic-fixture-token";
const PAT_TWO: &str = "gitlab-second-fixture-token";
const GH_PAT: &str = "github-hermetic-fixture-token";
/// A fixed 64-char hex token (valid shape) shared by server + client.
const TOKEN: &str = "abababababababababababababababababababababababababababababababab";

type TlsWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// In-memory [`TokenStore`] so tests never touch the real OS keychain.
#[derive(Default)]
struct MemTokenStore(Mutex<Option<String>>);

impl TokenStore for MemTokenStore {
    fn load_token(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn store_token(&self, token: &str) -> CoreResult<()> {
        *self.0.lock().unwrap() = Some(token.to_string());
        Ok(())
    }
}

/// Client cert verifier that pins the server's SHA-256 fingerprint (colon hex)
/// and otherwise validates the handshake signature with the ring provider.
#[derive(Debug)]
struct PinnedVerifier {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = Sha256::digest(end_entity.as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        if fp == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("fingerprint mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(fingerprint: &str) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            fingerprint: fingerprint.to_string(),
            provider,
        }))
        .with_no_client_auth();
    Arc::new(config)
}

struct Fixture {
    _ws: WsApiServer,
    mock: tokio::task::JoinHandle<()>,
    requests: Arc<Mutex<Vec<String>>>,
    instance: String,
    port: u16,
    cfg: Arc<ClientConfig>,
    dir: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.mock.abort();
    }
}
async fn boot() -> Fixture {
    let dir = common::test_tempdir("intentd-gitlab-wss-");
    let store = Store::open(&dir.path().join("intentd.db")).await.unwrap();
    let bus = EventBus::new(store.clone());
    let registry = Arc::new(SettingsRegistry::load(dir.path().join("config.toml")).unwrap());
    let services = Arc::new(
        Services::new(store)
            .with_workspaces_root(dir.path().join("workspaces"))
            .with_event_bus(bus.clone())
            .with_settings_registry(registry)
            .with_secret_store(Arc::new(InMemorySecretStore::default())),
    );
    let api: Arc<dyn WorkspaceApi> = services;
    let tls = ensure_tls_certificate(dir.path()).unwrap();
    let tokens = Arc::new(MemTokenStore::default());
    tokens.store_token(TOKEN).unwrap();
    let token_store = Arc::new(AsyncTokenStore::new(tokens));
    let server = WsApiServer::new(
        api,
        bus,
        &tls,
        &token_store,
        WsOptions {
            base_port: 0,
            bind_addresses: vec![Ipv4Addr::LOCALHOST.into()],
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let port = server.start().await.unwrap();
    let cfg = client_config(&tls.fingerprint256);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let instance = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let mock_instance = instance.clone();
    let mock = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut chunk = [0_u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(data).unwrap();
            let line = request.lines().next().unwrap().to_string();
            captured.lock().unwrap().push(line.clone());
            let target = line.split_whitespace().nth(1).unwrap();
            let raw_path = target.split('?').next().unwrap();
            let expected_token = if raw_path.starts_with("/github/") {
                GH_PAT
            } else if raw_path.starts_with("/second/") {
                PAT_TWO
            } else {
                PAT
            };
            assert!(
                request.lines().any(|line| {
                    line.split_once(':').is_some_and(|(key, val)| {
                        key.eq_ignore_ascii_case("authorization")
                            && val.trim() == format!("Bearer {expected_token}")
                    })
                }),
                "fixture requires the configured GitLab PAT"
            );
            let path = raw_path.strip_prefix("/second").unwrap_or(raw_path);
            let response_instance = if raw_path.starts_with("/second/") {
                format!("{mock_instance}/second")
            } else {
                mock_instance.clone()
            };
            let body = if path == "/github/user" {
                json!({"id":1,"login":"github-fixture","avatar_url":"https://github.com/avatar.png","html_url":"https://github.com/github-fixture"})
            } else if path == "/github/user/repos" {
                json!([{"id":42,"name":"widget","full_name":"euraika/widget","owner":{"login":"euraika"},"default_branch":"main","private":true,"html_url":"https://github.com/euraika/widget"}])
            } else if path == "/api/v4/user" {
                json!({"id": 12, "username": if raw_path.starts_with("/second/") { "second-fixture" } else { "bert-fixture" }, "name": "Bert", "avatar_url": null})
            } else if path.ends_with("/merge_requests/7") {
                json!({"id": 99, "iid": 7, "project_id": 42, "title": "GitLab native MR", "description": "Fixture", "state": "opened", "draft": false,
                    "source_branch": "feature", "target_branch": "main", "sha": "abc123", "detailed_merge_status": "mergeable", "has_conflicts": false,
                    "author": {"username": "bert-fixture"}, "web_url": format!("{response_instance}/euraika/platform/widget/-/merge_requests/7"),
                    "created_at": "2026-09-19T12:00:00Z", "updated_at": "2026-09-19T12:01:00Z"})
            } else if path.ends_with("/repository/branches") {
                json!([{"name": "main", "protected": true, "commit": {"id": "abc123"}}])
            } else if path == "/api/v4/projects" {
                json!([{"id": 42, "name": "widget", "path": "widget", "path_with_namespace": "euraika/platform/widget", "namespace": {"full_path": "euraika/platform"}, "default_branch": "main", "web_url": format!("{response_instance}/euraika/platform/widget")}])
            } else {
                panic!("unexpected fixture request: {line}")
            };
            let text = body.to_string();
            let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    Fixture {
        _ws: server,
        mock,
        requests,
        instance,
        port,
        cfg,
        dir,
    }
}
/// Establish an authenticated WSS connection over pinned TLS (token in the
/// query string).
async fn connect(port: u16, cfg: Arc<ClientConfig>) -> TlsWs {
    let url = format!("wss://localhost:{port}/ws?token={TOKEN}");
    common::wss_connect_with_retry(port, cfg, &url).await
}

/// Send a JSON-RPC request and return the full response envelope (success or
/// error) so tests can assert either arm.
async fn wss_rpc_envelope(ws: &mut TlsWs, id: i64, method: &str, params: Value) -> Value {
    let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    ws.send(Message::Text(req.to_string().into()))
        .await
        .unwrap();
    timeout(common::rpc_read_timeout(), async {
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Text(text) => {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    if v.get("id") == Some(&json!(id)) {
                        return v;
                    }
                }
                Message::Ping(p) => {
                    let _ = ws.send(Message::Pong(p)).await;
                }
                Message::Pong(_) => {}
                _ => panic!("unexpected message"),
            }
        }
    })
    .await
    .expect("response timeout")
}

async fn wss_rpc(ws: &mut TlsWs, id: i64, method: &str, params: Value) -> Value {
    let v = wss_rpc_envelope(ws, id, method, params).await;
    assert!(v.get("error").is_none(), "rpc {method} errored: {v}");
    v["result"].clone()
}

#[tokio::test]
async fn gitlab_settings_auth_browse_and_merge_request_over_wss() {
    let fx = boot().await;
    let mut ws = connect(fx.port, fx.cfg.clone()).await;
    let mut subscriber = connect(fx.port, fx.cfg.clone()).await;
    wss_rpc(
        &mut subscriber,
        100,
        "events.subscribe",
        json!({"eventTypes":["settings:changed"]}),
    )
    .await;
    let applied = wss_rpc(
        &mut ws,
        1,
        "settings.update",
        json!({"changes": [
            {"path":"sourceControl.activeProvider", "value":"gitlab"},
            {"path":"sourceControl.gitlab.instanceUrl", "value":fx.instance},
            {"path":"sourceControl.gitlab.tokenHost", "value":fx.instance},
            {"path":"sourceControl.gitlab.tokenSource", "value":"explicit"},
            {"path":"sourceControl.gitlab.token", "value":PAT}
        ]}),
    )
    .await;
    assert!(
        !applied.to_string().contains(PAT),
        "settings result must redact PAT"
    );
    let changed = timeout(common::rpc_read_timeout(), async {
        loop {
            match subscriber.next().await.unwrap().unwrap() {
                Message::Text(text) => {
                    let event: Value = serde_json::from_str(&text).unwrap();
                    if event["method"] == "events.event"
                        && event["params"]["event"]["type"] == "settings:changed"
                    {
                        return event;
                    }
                }
                Message::Ping(payload) => {
                    subscriber.send(Message::Pong(payload)).await.unwrap();
                }
                _ => {}
            }
        }
    })
    .await
    .expect("settings changed event");
    assert!(
        !changed.to_string().contains(PAT),
        "settings event must redact PAT"
    );
    let got = wss_rpc(
        &mut ws,
        2,
        "settings.get",
        json!({"path":"sourceControl.gitlab.token"}),
    )
    .await;
    assert!(
        !got.to_string().contains(PAT),
        "secret read must redact PAT"
    );
    let config = std::fs::read_to_string(fx.dir.path().join("config.toml")).unwrap();
    assert!(
        !config.contains(PAT),
        "PAT must never be stored in config.toml"
    );
    let auth = wss_rpc(
        &mut ws,
        3,
        "sourceControl.authStatus",
        json!({"connectionId":fx.instance}),
    )
    .await;
    assert_eq!(auth["connection"]["isConfigured"], true);
    let repos = wss_rpc(
        &mut ws,
        4,
        "sourceControl.repos.list",
        json!({"limit":10,"connectionId":fx.instance}),
    )
    .await;
    assert_eq!(repos["repos"][0]["owner"], "euraika/platform");
    let pull = wss_rpc(
        &mut ws,
        5,
        "sourceControl.pulls.get",
        json!({"connectionId":fx.instance,"owner":"euraika/platform", "repo":"widget", "number":7}),
    )
    .await;
    assert_eq!(
        pull["pull"]["number"], 7,
        "MR iid must be used, not global id"
    );
    assert_eq!(pull["pull"]["title"], "GitLab native MR");
    assert_eq!(pull["pull"]["headRef"], "feature");
    assert_eq!(pull["pull"]["state"], "open");
    let branches = wss_rpc(
        &mut ws,
        6,
        "sourceControl.branches.list",
        json!({"connectionId":fx.instance,"owner":"euraika/platform", "repo":"widget", "limit":10}),
    )
    .await;
    assert_eq!(branches["branches"][0], "main");
    let seen = fx.requests.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|s| s.contains("/projects/euraika%2Fplatform%2Fwidget/merge_requests/7")),
        "nested namespace must remain one encoded parameter: {seen:?}"
    );
    assert!(
        seen.iter().all(|s| s.starts_with("GET ")),
        "read workflows must not mutate GitLab"
    );
    let before = seen.len();
    // Reusing the PAT after changing the instance must fail before any network call.
    wss_rpc(
        &mut ws,
        7,
        "settings.update",
        json!({"changes":[
            {"path":"sourceControl.gitlab.instanceUrl", "value":"https://different.invalid"},
            {"path":"sourceControl.gitlab.tokenHost", "value":"https://different.invalid"}
        ]}),
    )
    .await;
    let denied = wss_rpc_envelope(
        &mut ws,
        8,
        "sourceControl.repos.list",
        json!({"connectionId":"https://different.invalid"}),
    )
    .await;
    assert!(
        denied.get("error").is_some(),
        "cross-host credential reuse must fail"
    );
    assert_eq!(fx.requests.lock().unwrap().len(), before);
}

#[tokio::test]
async fn independent_github_and_two_gitlab_connections_route_concurrent_wss_requests() {
    let fx = boot().await;
    let mut github = connect(fx.port, fx.cfg.clone()).await;
    let mut gitlab = connect(fx.port, fx.cfg.clone()).await;
    let mut second = connect(fx.port, fx.cfg.clone()).await;
    let second_instance = format!("{}/second", fx.instance);
    wss_rpc(
        &mut github,
        1,
        "settings.update",
        json!({"changes":[
            {"path":"sourceControl.github.tokenSource","value":"explicit"},
            {"path":"sourceControl.github.apiBaseUrl","value":format!("{}/github",fx.instance)},
            {"path":"sourceControl.github.token","value":GH_PAT},
            {"path":"sourceControl.activeProvider","value":"gitlab"}
        ]}),
    )
    .await;
    for (connection, token) in [(&fx.instance, PAT), (&second_instance, PAT_TWO)] {
        let result = wss_rpc(
            &mut github,
            2,
            "sourceControl.connections.configure",
            json!({
                "provider":"gitlab","instanceUrl":connection,"tokenSource":"explicit","token":token
            }),
        )
        .await;
        assert_eq!(result["connection"]["isConfigured"], true);
        assert!(!result.to_string().contains(token));
    }
    let (gh, gl, gl2) = tokio::join!(
        wss_rpc(&mut github, 3, "github.getUser", json!({})),
        wss_rpc(
            &mut gitlab,
            3,
            "sourceControl.getUser",
            json!({"connectionId":fx.instance})
        ),
        wss_rpc(
            &mut second,
            3,
            "sourceControl.getUser",
            json!({"connectionId":second_instance})
        )
    );
    assert_eq!(gh["user"]["login"], "github-fixture");
    assert_eq!(gl["user"]["login"], "bert-fixture");
    assert_eq!(gl2["user"]["login"], "second-fixture");
    let (gh, gl, gl2) = tokio::join!(
        wss_rpc(
            &mut github,
            4,
            "sourceControl.repos.list",
            json!({"connectionId":"https://github.com"})
        ),
        wss_rpc(
            &mut gitlab,
            4,
            "sourceControl.repos.list",
            json!({"connectionId":fx.instance})
        ),
        wss_rpc(
            &mut second,
            4,
            "sourceControl.repos.list",
            json!({"connectionId":second_instance})
        )
    );
    assert_eq!(
        gh["repos"][0]["htmlUrl"],
        "https://github.com/euraika/widget"
    );
    assert_eq!(
        gl["repos"][0]["htmlUrl"],
        format!("{}/euraika/platform/widget", fx.instance)
    );
    assert_eq!(
        gl2["repos"][0]["htmlUrl"],
        format!("{second_instance}/euraika/platform/widget")
    );
    let resolved = wss_rpc(
        &mut github,
        5,
        "sourceControl.resolve",
        json!({"repoUrl":format!("{second_instance}/euraika/platform/widget/-/merge_requests/7")}),
    )
    .await;
    assert_eq!(resolved["connectionId"], second_instance);
    assert_eq!(resolved["repo"]["owner"], "euraika/platform");
    assert_eq!(resolved["resource"], json!({"kind":"pr","number":7}));
    wss_rpc(
        &mut github,
        6,
        "sourceControl.connections.disconnect",
        json!({"connectionId":fx.instance}),
    )
    .await;
    let (gh, gl2) = tokio::join!(
        wss_rpc(&mut github, 7, "github.getUser", json!({})),
        wss_rpc(
            &mut second,
            7,
            "sourceControl.getUser",
            json!({"connectionId":second_instance})
        )
    );
    assert_eq!(gh["user"]["login"], "github-fixture");
    assert_eq!(gl2["user"]["login"], "second-fixture");
    let denied = wss_rpc_envelope(
        &mut gitlab,
        8,
        "sourceControl.getUser",
        json!({"connectionId":fx.instance}),
    )
    .await;
    assert!(denied.get("error").is_some());
    let config = std::fs::read_to_string(fx.dir.path().join("config.toml")).unwrap();
    for token in [PAT, PAT_TWO, GH_PAT] {
        assert!(!config.contains(token));
    }
}

#[tokio::test]
async fn gitlab_merge_request_url_creates_workspace_with_native_context() {
    let fx = boot().await;
    let mut ws = connect(fx.port, fx.cfg.clone()).await;
    wss_rpc(
        &mut ws,
        1,
        "sourceControl.connections.configure",
        json!({"provider":"gitlab","instanceUrl":fx.instance,"tokenSource":"explicit","token":PAT}),
    )
    .await;
    let repository = fx.dir.path().join("local-project");
    std::fs::create_dir(&repository).unwrap();
    let git = |args: &[&str]| {
        let result = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "git fixture failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    git(&["init", "-b", "main"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "Fixture",
    ]);
    git(&["branch", "feature"]);
    git(&[
        "remote",
        "add",
        "origin",
        &format!("{}/euraika/platform/widget.git", fx.instance),
    ]);
    let mr = format!("{}/euraika/platform/widget/-/merge_requests/7", fx.instance);
    let created = wss_rpc(&mut ws,2,"workspace.create",json!({
        "title":"GitLab MR fixture","repositoryPath":repository,"githubUrl":mr,"skipIsolation":true
    })).await;
    let workspace = &created["workspace"];
    assert_eq!(workspace["prUrl"], mr);
    assert_eq!(workspace["prNumber"], 7);
    assert_eq!(workspace["branch"], "feature");
    assert_eq!(workspace["baseRef"], "main");
    assert_eq!(workspace["repositoryOwner"], "euraika/platform");
    assert_eq!(workspace["repositoryName"], "widget");
    assert_eq!(workspace["contextLinks"][0]["kind"], "pr");
    assert_eq!(workspace["contextLinks"][0]["number"], 7);
    let resolution = wss_rpc(
        &mut ws,
        3,
        "sourceControl.resolve",
        json!({"workspaceId":workspace["id"]}),
    )
    .await;
    assert_eq!(resolution["connectionId"], fx.instance);
    assert_eq!(resolution["repo"]["owner"], "euraika/platform");
    let conflict = wss_rpc_envelope(&mut ws,4,"sourceControl.resolve",json!({"workspaceId":workspace["id"],"repoUrl":format!("{}/different/project",fx.instance)})).await;
    assert!(
        conflict.get("error").is_some(),
        "same host does not authorize replacing a workspace's repository"
    );
}
