//! Persistent Codex storage for Intent. Existing native sessions stay in their
//! original home until an explicit migration can preserve their resume IDs.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn key(value: &str) -> String {
    use std::fmt::Write;
    Sha256::digest(value.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Match the usual login remedy to the home actually used by this agent.
/// Keychain entries are namespaced by Codex home, so a normal `codex login`
/// would otherwise authenticate the desktop again instead of this session.
pub(crate) fn login_command(root: &Path, agent: &str) -> Option<String> {
    let home = std::fs::read_to_string(root.join("agents").join(key(agent))).ok()?;
    Some(format!(
        "CODEX_HOME='{}' codex login",
        home.replace('\'', "'\\''")
    ))
}

pub(crate) fn user_home() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_HOME").filter(|p| !p.is_empty()) {
        return std::path::absolute(PathBuf::from(path));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join(".codex"))
        .ok_or_else(|| io::Error::other("Cannot resolve the user's Codex home"))
}

/// Return the selected home. A durable per-agent marker distinguishes sessions
/// created here from pre-upgrade sessions, including across daemon restarts.
pub(crate) fn prepare(
    root: &Path,
    source: &Path,
    agent: &str,
    has_native_session: bool,
) -> io::Result<PathBuf> {
    private_dir(root)?;
    let root = root.canonicalize()?;
    let marker_dir = root.join("agents");
    private_dir(&marker_dir)?;
    let marker = marker_dir.join(key(agent));
    let selected = match std::fs::read_to_string(&marker) {
        Ok(path) => PathBuf::from(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if has_native_session {
                // Do not silently lose native context by attempting to load an
                // old ID from an empty home. Legacy chats remain visible.
                return Ok(source.to_path_buf());
            }
            root.join("homes").join(key(&source.to_string_lossy()))
        }
        Err(e) => return Err(e),
    };
    if selected.parent() != Some(root.join("homes").as_path())
        || !selected
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(io::Error::other("Invalid Intent Codex home marker"));
    }
    private_dir(&root.join("homes"))?;
    private_dir(&selected)?;
    // Share configuration resources, never sessions, indexes or databases.
    // A symlink (not a snapshot) keeps file-auth refreshes and subsequent
    // login replacements visible to both applications. Codex writes auth.json
    // in place; Intent never reads or logs credential bytes.
    for name in [
        "skills",
        "plugins",
        "rules",
        "AGENTS.md",
        "AGENTS.override.md",
        "instructions.md",
        "hooks.json",
        ".credentials.json",
    ] {
        // An absent resource must not become a dangling directory symlink:
        // Codex may create its own system skills in an otherwise empty home.
        if source.join(name).exists() && !selected.join(name).exists() {
            link(&source.join(name), &selected.join(name))?;
        }
    }
    link(&source.join("auth.json"), &selected.join("auth.json"))?;
    write_config(source, &selected)?;
    // Record routing before spawn: retries must select the same storage.
    atomic_write(&marker, selected.to_string_lossy().as_bytes())?;
    Ok(selected)
}

fn write_config(source: &Path, home: &Path) -> io::Result<()> {
    let text = match std::fs::read_to_string(source.join("config.toml")) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let mut config = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| io::Error::other(format!("Invalid Codex config: {e}")))?;
    // A user-level SQLite override must not reconnect the isolated sessions
    // to the desktop's index. Preserve every unrelated setting.
    config["sqlite_home"] = toml_edit::value(home.to_string_lossy().as_ref());
    if let Some(profiles) = config
        .get_mut("profiles")
        .and_then(|v| v.as_table_like_mut())
    {
        for (_, profile) in profiles.iter_mut() {
            if let Some(table) = profile.as_table_like_mut() {
                table.remove("sqlite_home");
            }
        }
    }
    atomic_write(&home.join("config.toml"), config.to_string().as_bytes())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    file.write_all(bytes)?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn private_dir(path: &Path) -> io::Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::other("Codex storage must be a real directory"));
        }
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn link(source: &Path, target: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(target) {
        Ok(_) if std::fs::read_link(target).ok().as_deref() == Some(source) => return Ok(()),
        Ok(_) => {
            return Err(io::Error::other(format!(
                "Refusing to replace {}",
                target.display()
            )))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        match std::os::unix::fs::symlink(source, target) {
            Ok(()) => Ok(()),
            Err(e)
                if e.kind() == io::ErrorKind::AlreadyExists
                    && std::fs::read_link(target).ok().as_deref() == Some(source) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    Err(io::Error::other(
        "Isolated Codex storage requires filesystem symlink support",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn separates_state_and_keeps_file_auth_live_across_restarts() {
        let tmp = crate::test_support::test_tempdir("codex-home-");
        let source = tmp.path().join("user");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("auth.json"), "initial-test-credential").unwrap();
        std::fs::write(source.join("config.toml"), "model = 'test-model'\nsqlite_home = '/shared'\n[profiles.work]\nsqlite_home = '/also-shared'\n").unwrap();
        let root = tmp.path().join("intent");
        let home = prepare(&root, &source, "agent-1", false).unwrap();
        assert_ne!(home, source);
        assert_eq!(
            login_command(&root, "agent-1"),
            Some(format!("CODEX_HOME='{}' codex login", home.display()))
        );
        std::fs::create_dir(home.join("skills")).unwrap();
        std::fs::create_dir(home.join("sessions")).unwrap();
        std::fs::write(home.join("sessions/session"), "native-context").unwrap();
        assert!(!source.join("sessions").exists());
        std::fs::write(home.join("auth.json"), "refreshed-test-credential").unwrap();
        assert_eq!(
            std::fs::read_to_string(source.join("auth.json")).unwrap(),
            "refreshed-test-credential"
        );
        atomic_write(&source.join("auth.json"), b"replacement-login").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("auth.json")).unwrap(),
            "replacement-login"
        );
        assert_eq!(prepare(&root, &source, "agent-1", true).unwrap(), home);
        assert_eq!(
            std::fs::read_to_string(home.join("sessions/session")).unwrap(),
            "native-context"
        );
        let config = std::fs::read_to_string(home.join("config.toml"))
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        assert_eq!(config["model"].as_str(), Some("test-model"));
        assert_eq!(config["sqlite_home"].as_str(), home.to_str());
        assert!(config["profiles"]["work"].get("sqlite_home").is_none());
    }

    #[test]
    fn legacy_sessions_keep_their_original_storage() {
        let tmp = crate::test_support::test_tempdir("codex-legacy-");
        let source = tmp.path().join("user");
        let root = tmp.path().join("intent");
        assert_eq!(prepare(&root, &source, "old-agent", true).unwrap(), source);
        assert!(login_command(&root, "old-agent").is_none());
        assert!(!source.exists());
        assert!(!root.join("agents").join(key("old-agent")).exists());
    }

    #[test]
    fn refuses_to_overwrite_existing_auth_material() {
        let tmp = crate::test_support::test_tempdir("codex-auth-");
        let target = tmp.path().join("auth.json");
        std::fs::write(&target, "keep-me").unwrap();
        assert!(link(&tmp.path().join("source"), &target).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "keep-me");
    }
}
