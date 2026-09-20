//! Real private HTTPS Git: clone, fetch and helper-authenticated push against a local TLS
//! smart-HTTP server. Every token is synthetic; all repositories are temporary.
#![cfg(unix)]
mod common;

use base64::Engine;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn git(dir: &Path, args: &[&str]) {
    let _ = git_output(dir, args);
}

fn git_output(dir: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_string()
}

fn pem_bytes(pem: &str) -> Vec<u8> {
    let data: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_https_clone_fetch_and_push_use_the_instance_credential() {
    let dir = common::test_tempdir_in("/tmp", "itd-gl-https-");
    let root = dir.path();
    git(
        root,
        &["init", "--bare", "--initial-branch=main", "project.git"],
    );
    git(
        &root.join("project.git"),
        &["config", "http.receivepack", "true"],
    );
    git(root, &["init", "--initial-branch=main", "seed"]);
    let seed = root.join("seed");
    git(&seed, &["config", "user.name", "Fixture"]);
    git(&seed, &["config", "user.email", "fixture@example.invalid"]);
    std::fs::write(seed.join("README.md"), "initial\n").unwrap();
    git(&seed, &["add", "README.md"]);
    git(&seed, &["commit", "-m", "initial"]);
    git(&seed, &["push", "../project.git", "main"]);

    let certificate = intent_transport::ensure_tls_certificate(root).unwrap();
    let cert_path = root.join("fixture-cert.pem");
    std::fs::write(&cert_path, &certificate.cert).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![pem_bytes(&certificate.cert).into()],
        rustls_pki_types::PrivatePkcs8KeyDer::from(pem_bytes(&certificate.key)).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let instance = format!(
        "https://localhost:{}/gitlab",
        listener.local_addr().unwrap().port()
    );
    let server_root = root.to_path_buf();
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server_served = served.clone();
    let redirected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server_redirected = redirected.clone();
    let listener_task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let root = server_root.clone();
            let served = server_served.clone();
            let redirected = server_redirected.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                    assert!(request.len() < 65536);
                }
                let headers = String::from_utf8(request).unwrap();
                let mut first = headers.lines().next().unwrap().split_whitespace();
                let method = first.next().unwrap().to_string();
                let target = first.next().unwrap().to_string();
                if target.starts_with("/outside/") {
                    redirected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    return;
                }
                let header = |name: &str| {
                    headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.trim().to_string())
                };
                let expected = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode("oauth2:fixture-https-token")
                );
                if header("authorization").as_deref() != Some(&expected) {
                    stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    return;
                }
                served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(suffix) = target.strip_prefix("/gitlab/redirect.git") {
                    let response = format!("HTTP/1.1 302 Found\r\nLocation: /outside/project.git{suffix}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    stream.write_all(response.as_bytes()).await.unwrap();
                    return;
                }
                if header("expect").as_deref() == Some("100-continue") {
                    stream
                        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                        .await
                        .unwrap();
                }
                let length = header("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                assert!(length < 2_000_000);
                assert!(
                    header("transfer-encoding").is_none(),
                    "small fixture requests use Content-Length"
                );
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let content_type = header("content-type").unwrap_or_default();
                let git_protocol = header("git-protocol").unwrap_or_default();
                let result = tokio::task::spawn_blocking(move || {
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let path = path.strip_prefix("/gitlab/team/project.git").unwrap();
                    let mut child = Command::new("git")
                        .arg("http-backend")
                        .env("GIT_PROJECT_ROOT", root)
                        .env("GIT_HTTP_EXPORT_ALL", "1")
                        .env("PATH_INFO", format!("/project.git{path}"))
                        .env("REQUEST_METHOD", method)
                        .env("QUERY_STRING", query)
                        .env("CONTENT_TYPE", content_type)
                        .env("CONTENT_LENGTH", body.len().to_string())
                        .env("HTTP_GIT_PROTOCOL", git_protocol)
                        .env("REMOTE_USER", "oauth2")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap();
                    child.stdin.take().unwrap().write_all(&body).unwrap();
                    child.wait_with_output().unwrap()
                })
                .await
                .unwrap();
                assert!(result.status.success());
                let end = result
                    .stdout
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .unwrap();
                let cgi_headers = String::from_utf8_lossy(&result.stdout[..end]);
                let response_body = &result.stdout[end + 4..];
                let response = format!("HTTP/1.1 200 OK\r\n{cgi_headers}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response_body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(response_body).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    // A separate process keeps Git's CA/config environment hermetic without
    // changing process-global variables underneath parallel tests.
    let global = root.join("gitconfig");
    std::fs::write(
        &global,
        format!(
            "[http]\nsslCAInfo = {}\n[credential]\nhelper =\n",
            cert_path.display()
        ),
    )
    .unwrap();
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "https_git_transport_child",
            "--ignored",
            "--nocapture",
        ])
        .env("INTENT_HTTPS_FIXTURE", &instance)
        .env("INTENT_HTTPS_ROOT", root)
        .env("GIT_CONFIG_GLOBAL", global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_SSL_CAINFO", cert_path)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(45), command.output())
        .await
        .unwrap()
        .unwrap();
    listener_task.abort();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(served.load(std::sync::atomic::Ordering::Relaxed) >= 5);
    assert_eq!(
        redirected.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "credentialed Git must never follow a same-host redirect outside the installation"
    );
}

#[test]
#[ignore = "invoked in a hermetic subprocess by the HTTPS integration test"]
fn https_git_transport_child() {
    let instance = std::env::var("INTENT_HTTPS_FIXTURE").unwrap();
    let root = std::path::PathBuf::from(std::env::var_os("INTENT_HTTPS_ROOT").unwrap());
    let url = format!("{instance}/team/project.git");
    let credential =
        intent_git::auth::GitCredential::new(&instance, "oauth2", "fixture-https-token").unwrap();
    let cloned = root.join("cloned");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let cache_root = root.join("repo-cache");
    let cached = runtime
        .block_on(intent_git::repo_cache::ensure_cached_repo(
            &cache_root,
            &url,
            "team",
            "project",
            Some(&credential),
        ))
        .unwrap();
    assert!(cached.starts_with(cache_root.join(".forges")));
    assert!(runtime
        .block_on(intent_git::repo_cache::list_cached_branches_for_url(
            &cache_root,
            "team",
            "project",
            &url,
        ))
        .unwrap()
        .is_some());
    intent_git::repo_cache::provision_direct_checkout_with_progress(
        &cached, &cloned, &url, "main", None, None,
    )
    .unwrap();
    let branches = runtime
        .block_on(intent_git::ls_remote::ls_remote_branches(
            &url,
            Some(&credential),
        ))
        .unwrap();
    assert!(!branches.branches.is_empty());
    // Only this isolated child mutates its environment. After cloning, the CA
    // exists solely in this repository's config, proving every production
    // worktree operation (including the branch probe) runs in that worktree.
    let certificate = std::env::var("GIT_SSL_CAINFO").unwrap();
    git(&cloned, &["config", "http.sslCAInfo", &certificate]);
    std::env::remove_var("GIT_SSL_CAINFO");
    std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
    intent_git::fetch::fetch(&cloned, "origin", "main", Some(&credential)).unwrap();
    git(&cloned, &["config", "user.name", "Fixture"]);
    git(
        &cloned,
        &["config", "user.email", "fixture@example.invalid"],
    );
    std::fs::write(cloned.join("README.md"), "pushed over HTTPS\n").unwrap();
    git(&cloned, &["commit", "-am", "HTTPS push"]);
    let outcome =
        intent_git::push::push(&cloned, "origin", "main", false, Some(&credential)).unwrap();
    assert_eq!(outcome.branch, "main");
    assert_eq!(
        intent_git::remote::ls_remote_has_branch(&cloned, "origin", "main", Some(&credential))
            .unwrap(),
        intent_git::remote::RemoteBranch::Present,
    );
    assert_eq!(
        intent_git::remote::ls_remote_has_branch(&cloned, "origin", "absent", Some(&credential))
            .unwrap(),
        intent_git::remote::RemoteBranch::Missing,
    );
    let refspec_sha = intent_git::push::push_refspec(
        &cloned,
        "origin",
        "HEAD",
        "second",
        false,
        Some(&credential),
    )
    .unwrap();
    assert_eq!(outcome.pushed_sha, refspec_sha);
    let previous = git_output(&cloned, &["rev-parse", "HEAD~1"]);
    // Rejected non-fast-forward pushes must neither claim success nor advance
    // tracking refs; the explicit force variant must rewind both sides.
    assert!(intent_git::push::push_refspec(
        &cloned,
        "origin",
        "HEAD~1",
        "second",
        false,
        Some(&credential)
    )
    .is_err());
    let tracking = || git_output(&cloned, &["rev-parse", "refs/remotes/origin/second"]);
    assert_eq!(tracking(), refspec_sha);
    assert_eq!(
        intent_git::push::push_refspec(
            &cloned,
            "origin",
            "HEAD~1",
            "second",
            true,
            Some(&credential)
        )
        .unwrap(),
        previous
    );
    assert_eq!(tracking(), previous);
    assert_eq!(
        git_output(
            &root.join("project.git"),
            &["rev-parse", "refs/heads/second"]
        ),
        previous
    );
    assert!(git_output(&cloned, &["for-each-ref", "refs/intent/tmp-push-*"]).is_empty());
    let pushed = Command::new("git")
        .arg("-C")
        .arg(&cloned)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let actual = Command::new("git")
        .arg("-C")
        .arg(root.join("project.git"))
        .args(["rev-parse", "main"])
        .output()
        .unwrap();
    assert_eq!(actual.stdout, pushed.stdout);
    // Git URL-specific config is more specific than a generic command-level
    // http.followRedirects=false. The credential guard must override this key
    // too; otherwise libcurl reuses Authorization beyond the install prefix.
    git(
        &cloned,
        &[
            "config",
            &format!("http.{instance}/redirect.git.followRedirects"),
            "true",
        ],
    );
    git(
        &cloned,
        &[
            "remote",
            "set-url",
            "origin",
            &format!("{instance}/redirect.git"),
        ],
    );
    assert!(intent_git::push::push(&cloned, "origin", "main", false, Some(&credential)).is_err());
    assert!(intent_git::push::push_refspec(
        &cloned,
        "origin",
        "HEAD",
        "second",
        false,
        Some(&credential)
    )
    .is_err());
    assert!(
        intent_git::remote::ls_remote_has_branch(&cloned, "origin", "main", Some(&credential))
            .is_err()
    );
}
