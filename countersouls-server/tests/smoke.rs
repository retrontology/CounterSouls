use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use countersouls_protocol::{ClientMessage, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_smoke_test() -> Result<()> {
    let port = free_port()?;
    let data_dir = unique_temp_dir();
    fs::create_dir_all(&data_dir)?;

    let bin = resolve_server_binary()?;
    let mut child = Command::new(bin)
        .arg("--password")
        .arg("smoke-pass")
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--data-dir")
        .arg(&data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start server process")?;
    if let Some(status) = child.try_wait()? {
        bail!("server exited too early: {status}");
    }
    let _guard = ChildGuard { child };

    wait_for_server(port).await?;
    let ws_url = format!("ws://127.0.0.1:{port}");

    let (mut alice_ws, _) = connect_and_auth(&ws_url, "alice").await?;
    send_client_msg(&mut alice_ws, &ClientMessage::Update { count: 3 }).await?;

    let (mut bob_ws, bob_counts) = connect_and_auth(&ws_url, "bob").await?;
    assert_eq!(bob_counts.get("alice"), Some(&3));
    send_client_msg(&mut bob_ws, &ClientMessage::Update { count: 7 }).await?;

    expect_update_for(&mut alice_ws, "bob", 7).await?;

    let (mut alice_ws_2, _) = connect_and_auth(&ws_url, "alice").await?;
    send_client_msg(&mut alice_ws_2, &ClientMessage::Update { count: 9 }).await?;

    send_client_msg(&mut bob_ws, &ClientMessage::RequestAll).await?;
    let counts = expect_all_counts(&mut bob_ws).await?;
    assert_eq!(counts.get("alice"), Some(&9));
    assert_eq!(counts.get("bob"), Some(&7));

    alice_ws.close(None).await?;
    bob_ws.close(None).await?;
    alice_ws_2.close(None).await?;

    // Give the server a brief moment to flush final writes.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(read_first_line(&data_dir.join("alice"))?, "9");
    assert_eq!(read_first_line(&data_dir.join("bob"))?, "7");

    let _ = fs::remove_dir_all(data_dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_auth_failure_returns_auth_error() -> Result<()> {
    let port = free_port()?;
    let data_dir = unique_temp_dir();
    fs::create_dir_all(&data_dir)?;

    let bin = resolve_server_binary()?;
    let mut child = Command::new(bin)
        .arg("--password")
        .arg("correct-pass")
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--data-dir")
        .arg(&data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start server process")?;
    if let Some(status) = child.try_wait()? {
        bail!("server exited too early: {status}");
    }
    let _guard = ChildGuard { child };

    wait_for_server(port).await?;
    let ws_url = format!("ws://127.0.0.1:{port}");
    let (mut ws, _) = connect_async(&ws_url).await?;

    send_client_msg(
        &mut ws,
        &ClientMessage::Auth {
            password: "wrong-pass".to_string(),
            name: "alice".to_string(),
        },
    )
    .await?;

    match recv_server_msg(&mut ws).await? {
        ServerMessage::AuthError { reason } => {
            assert!(
                reason.to_lowercase().contains("invalid password"),
                "unexpected auth error reason: {reason}"
            );
        }
        other => bail!("expected auth_error, got {other:?}"),
    }

    let _ = ws.close(None).await;
    let _ = fs::remove_dir_all(data_dir);
    Ok(())
}

async fn connect_and_auth(
    ws_url: &str,
    name: &str,
) -> Result<(
    WebSocketStream<MaybeTlsStream<TcpStream>>,
    std::collections::BTreeMap<String, u64>,
)> {
    let (mut ws, _) = connect_async(ws_url).await?;
    send_client_msg(
        &mut ws,
        &ClientMessage::Auth {
            password: "smoke-pass".to_string(),
            name: name.to_string(),
        },
    )
    .await?;

    let auth = recv_server_msg(&mut ws).await?;
    if !matches!(auth, ServerMessage::AuthOk) {
        bail!("expected auth_ok, got {auth:?}");
    }

    match recv_server_msg(&mut ws).await? {
        ServerMessage::All { counts } => Ok((ws, counts)),
        other => bail!("expected all snapshot, got {other:?}"),
    }
}

async fn send_client_msg(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    msg: &ClientMessage,
) -> Result<()> {
    let raw = serde_json::to_string(msg)?;
    ws.send(Message::Text(raw.into())).await?;
    Ok(())
}

async fn recv_server_msg(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<ServerMessage> {
    let frame = timeout(Duration::from_secs(3), ws.next())
        .await
        .context("timeout waiting for server frame")?
        .ok_or_else(|| anyhow::anyhow!("websocket ended"))??;

    let raw = match frame {
        Message::Text(txt) => txt.to_string(),
        Message::Binary(bin) => String::from_utf8(bin.to_vec())?,
        other => bail!("unexpected websocket frame: {other:?}"),
    };
    Ok(serde_json::from_str::<ServerMessage>(&raw)?)
}

async fn expect_update_for(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    name: &str,
    expected_count: u64,
) -> Result<()> {
    for _ in 0..5 {
        match recv_server_msg(ws).await? {
            ServerMessage::Update {
                name: update_name,
                count,
            } if update_name == name && count == expected_count => {
                return Ok(());
            }
            _ => {}
        }
    }
    bail!("did not receive update for {name}={expected_count}");
}

async fn expect_all_counts(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<std::collections::BTreeMap<String, u64>> {
    for _ in 0..5 {
        if let ServerMessage::All { counts } = recv_server_msg(ws).await? {
            return Ok(counts);
        }
    }
    bail!("did not receive all snapshot");
}

async fn wait_for_server(port: u16) -> Result<()> {
    for _ in 0..30 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("server did not become ready on port {port}");
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn unique_temp_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("countersouls-smoke-{nanos}"))
}

fn read_first_line(path: &Path) -> Result<String> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(content
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string())
}

fn resolve_server_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_countersouls-server") {
        return Ok(PathBuf::from(path));
    }

    let current = std::env::current_exe().context("failed to resolve current test exe path")?;
    let debug_dir = current
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("failed to infer target debug directory"))?;
    let candidate = debug_dir.join("countersouls-server");
    if candidate.exists() {
        return Ok(candidate);
    }

    // Ensure the server binary exists for environments that don't expose CARGO_BIN_EXE_*.
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("countersouls-server")
        .current_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .ok_or_else(|| anyhow::anyhow!("failed to find workspace root"))?,
        )
        .status()
        .context("failed to run cargo build for server binary")?;
    if !status.success() {
        bail!("cargo build failed while preparing server binary");
    }

    if candidate.exists() {
        Ok(candidate)
    } else {
        bail!("server binary not found at {}", candidate.display())
    }
}
