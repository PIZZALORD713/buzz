//! Lifecycle management for the embedded single-node relay.
//!
//! The relay remains the source of truth for local-mode behavior. Desktop only
//! chooses private loopback ports, supplies its identity and durable paths, and
//! supervises the bundled `buzz-relay` binary.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

use nostr::Keys;
use tauri::{AppHandle, Manager};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct LocalRelayRuntime {
    child: Child,
    url: String,
    owner_pubkey: String,
}

pub(crate) type RuntimeState = Mutex<Option<LocalRelayRuntime>>;

#[derive(Debug, PartialEq, Eq)]
struct LocalRelayConfig {
    relay_addr: SocketAddr,
    health_port: u16,
    metrics_port: u16,
    data_dir: PathBuf,
    owner_pubkey: String,
    relay_private_key: String,
}

impl LocalRelayConfig {
    fn url(&self) -> String {
        format!("ws://{}", self.relay_addr)
    }

    fn environment(&self) -> Vec<(&'static str, String)> {
        let db_path = self.data_dir.join("relay.sqlite3");
        let media_dir = self.data_dir.join("media");
        vec![
            ("BUZZ_PROFILE", "single-node".to_string()),
            ("BUZZ_BIND_ADDR", self.relay_addr.to_string()),
            ("BUZZ_HEALTH_PORT", self.health_port.to_string()),
            ("BUZZ_METRICS_PORT", self.metrics_port.to_string()),
            ("RELAY_URL", self.url()),
            ("BUZZ_LOCAL_DB", sqlite_url(&db_path)),
            ("BUZZ_LOCAL_MEDIA_DIR", media_dir.display().to_string()),
            ("BUZZ_REQUIRE_RELAY_MEMBERSHIP", "true".to_string()),
            ("RELAY_OWNER_PUBKEY", self.owner_pubkey.clone()),
            ("BUZZ_RELAY_PRIVATE_KEY", self.relay_private_key.clone()),
        ]
    }
}

impl LocalRelayRuntime {
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    fn stop(&mut self) {
        // The relay handles SIGTERM with a WebSocket drain. It is our child, so
        // waiting here prevents a restart from inheriting a stale listener.
        #[cfg(unix)]
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        #[cfg(windows)]
        let _ = self.child.kill();

        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts a relay for this desktop identity and waits for the public relay-info
/// endpoint. `Db::new_sqlite` in the relay applies its versioned SQLite
/// migrations before this endpoint can become available.
pub(crate) fn start(
    app: &AppHandle,
    keys: &Keys,
    requested_port: Option<u16>,
) -> Result<LocalRelayRuntime, String> {
    let relay_port = requested_port.unwrap_or(free_loopback_port()?);
    let owner_pubkey = keys.public_key().to_hex();
    let config = LocalRelayConfig {
        relay_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port),
        health_port: free_loopback_port()?,
        metrics_port: free_loopback_port()?,
        data_dir: local_data_dir(app, &owner_pubkey)?,
        owner_pubkey,
        relay_private_key: keys.secret_key().to_secret_hex(),
    };
    let url = config.url();
    let media_dir = config.data_dir.join("media");
    std::fs::create_dir_all(&media_dir)
        .map_err(|e| format!("create local relay media dir: {e}"))?;

    let binary = relay_binary()?;
    let mut command = Command::new(&binary);
    command
        .envs(config.environment())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| format!("start bundled buzz-relay at {}: {e}", binary.display()))?;

    let info_url = format!("http://{}/info", config.relay_addr);
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|e| format!("inspect local relay: {e}"))?
            .is_some()
        {
            return Err("bundled buzz-relay exited before becoming ready".to_string());
        }
        if reqwest::blocking::Client::new()
            .get(&info_url)
            .header("Accept", "application/nostr+json")
            .send()
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(LocalRelayRuntime {
                child,
                url,
                owner_pubkey: config.owner_pubkey,
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    let _ = child.kill();
    let _ = child.wait();
    Err("bundled buzz-relay did not become ready within 15 seconds".to_string())
}

pub(crate) fn ensure_started(
    app: &AppHandle,
    runtime: &RuntimeState,
    keys: &Keys,
    requested_port: Option<u16>,
) -> Result<String, String> {
    let mut runtime = runtime.lock().map_err(|error| error.to_string())?;
    if let Some(running) = runtime.as_ref() {
        let same_port = requested_port.is_none_or(|port| running.url == local_relay_url(port));
        let same_owner = running.owner_pubkey == keys.public_key().to_hex();
        if same_port && same_owner {
            return Ok(running.url().to_string());
        }
        if !same_owner {
            // An onboarding identity import changed the owner. Its local relay
            // must use a separate identity-scoped nest, not retain the prior
            // identity's private sidecar.
            if let Some(mut previous) = runtime.take() {
                previous.stop();
            }
        } else {
            return Err("a different local relay port is already running".to_string());
        }
    }
    let started = start(app, keys, requested_port)?;
    let url = started.url().to_string();
    *runtime = Some(started);
    Ok(url)
}

pub(crate) fn stop(runtime: &RuntimeState) {
    if let Ok(mut runtime) = runtime.lock() {
        if let Some(mut runtime) = runtime.take() {
            runtime.stop();
        }
    }
}

/// The persisted sentinel for the desktop-owned local workspace. It is never a
/// network endpoint: `apply_workspace` resolves it to the current supervised
/// loopback URL before any client or managed agent is restored.
pub(crate) const LOCAL_RELAY_SENTINEL: &str = "buzz-local://on-this-device";

pub(crate) fn is_local_relay_url(url: &str) -> bool {
    url == LOCAL_RELAY_SENTINEL
}

fn local_relay_url(port: u16) -> String {
    format!("ws://127.0.0.1:{port}")
}

pub(crate) fn relay_url(runtime: &RuntimeState) -> Option<String> {
    runtime
        .lock()
        .ok()
        .and_then(|runtime| runtime.as_ref().map(|runtime| runtime.url().to_string()))
}

fn local_data_dir(app: &AppHandle, owner_pubkey: &str) -> Result<PathBuf, String> {
    // Relay state is both durable and identity-scoped. A different desktop
    // identity must never inherit this identity's SQLite membership or media.
    app.path()
        .app_data_dir()
        .map(|path| path.join("local-relay").join(owner_pubkey))
        .map_err(|e| format!("resolve app data directory for local relay: {e}"))
}

fn sqlite_url(path: &Path) -> String {
    // sqlx accepts an absolute sqlite URL with three slashes. Path display is
    // intentional: app-data paths come from the OS, not user relay input.
    format!("sqlite://{}", path.display())
}

fn free_loopback_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| format!("pick local relay port: {e}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|e| format!("read local relay port: {e}"))
}

fn relay_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("resolve desktop executable: {e}"))?;
    let parent = exe
        .parent()
        .ok_or("desktop executable has no parent directory")?;
    let name = if cfg!(windows) {
        "buzz-relay.exe"
    } else {
        "buzz-relay"
    };
    let binary = parent.join(name);
    if binary.is_file() {
        Ok(binary)
    } else {
        Err(format!(
            "bundled buzz-relay is missing at {}",
            binary.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_local_relay_url, local_relay_url, sqlite_url, LocalRelayConfig, LOCAL_RELAY_SENTINEL,
    };
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
    };

    #[test]
    fn sqlite_url_is_absolute() {
        assert_eq!(
            sqlite_url(Path::new("/tmp/buzz.sqlite3")),
            "sqlite:///tmp/buzz.sqlite3"
        );
    }

    #[test]
    fn local_relay_sentinel_is_the_only_managed_workspace_address() {
        assert_eq!(local_relay_url(4317), "ws://127.0.0.1:4317");
        assert!(is_local_relay_url(LOCAL_RELAY_SENTINEL));
        assert!(!is_local_relay_url("ws://127.0.0.1:4317"));
        assert!(!is_local_relay_url("ws://localhost:4317"));
        assert!(!is_local_relay_url("wss://127.0.0.1:4317"));
    }

    #[test]
    fn local_relay_environment_uses_only_the_single_node_contract() {
        let config = LocalRelayConfig {
            relay_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4317),
            health_port: 4318,
            metrics_port: 4319,
            data_dir: PathBuf::from("/tmp/buzz/local-relay"),
            owner_pubkey: "owner".to_string(),
            relay_private_key: "private".to_string(),
        };
        let env: HashMap<_, _> = config.environment().into_iter().collect();

        assert_eq!(env.get("BUZZ_PROFILE"), Some(&"single-node".to_string()));
        assert_eq!(
            env.get("BUZZ_BIND_ADDR"),
            Some(&"127.0.0.1:4317".to_string())
        );
        assert_eq!(
            env.get("RELAY_URL"),
            Some(&"ws://127.0.0.1:4317".to_string())
        );
        assert_eq!(
            env.get("BUZZ_LOCAL_DB"),
            Some(&"sqlite:///tmp/buzz/local-relay/relay.sqlite3".to_string())
        );
        assert_eq!(
            env.get("BUZZ_LOCAL_MEDIA_DIR"),
            Some(&"/tmp/buzz/local-relay/media".to_string())
        );
        assert_eq!(
            env.get("BUZZ_REQUIRE_RELAY_MEMBERSHIP"),
            Some(&"true".to_string())
        );
        assert_eq!(env.get("RELAY_OWNER_PUBKEY"), Some(&"owner".to_string()));
        assert_eq!(
            env.get("BUZZ_RELAY_PRIVATE_KEY"),
            Some(&"private".to_string())
        );
    }
}
