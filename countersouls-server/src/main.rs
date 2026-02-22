use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use clap::Parser;
use countersouls_protocol::{ClientMessage, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    fs,
    net::{TcpListener, TcpStream},
    sync::{
        RwLock,
        mpsc::{UnboundedSender, unbounded_channel},
    },
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[derive(Parser, Debug, Clone)]
#[command(name = "countersouls-server")]
struct Args {
    #[arg(long, default_value = "./deaths/")]
    data_dir: PathBuf,
    #[arg(long)]
    password: String,
    #[arg(long, default_value = "0.0.0.0:3721")]
    bind: String,
}

#[derive(Clone)]
struct ClientHandle {
    id: u64,
    tx: UnboundedSender<ServerMessage>,
}

#[derive(Default)]
struct State {
    counts: RwLock<HashMap<String, u64>>,
    clients: RwLock<Vec<ClientHandle>>,
    next_id: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.data_dir)
        .await
        .with_context(|| format!("failed to create data dir {}", args.data_dir.display()))?;

    let state = Arc::new(State::default());
    let loaded = load_counts(&args.data_dir).await?;
    {
        let mut counts = state.counts.write().await;
        *counts = loaded;
    }

    let listener = TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind to {}", args.bind))?;
    println!("server listening on {}", args.bind);
    println!("data dir: {}", args.data_dir.display());

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();
        let args = args.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state, args).await {
                eprintln!("connection {} error: {err:#}", peer_addr);
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, state: Arc<State>, args: Args) -> Result<()> {
    let ws = accept_async(stream)
        .await
        .context("websocket handshake failed")?;
    let (mut ws_writer, mut ws_reader) = ws.split();
    let (server_tx, mut server_rx) = unbounded_channel::<ServerMessage>();
    let client_id = state.next_id.fetch_add(1, Ordering::Relaxed);

    {
        let mut clients = state.clients.write().await;
        clients.push(ClientHandle {
            id: client_id,
            tx: server_tx.clone(),
        });
    }

    let writer_task = tokio::spawn(async move {
        while let Some(outgoing) = server_rx.recv().await {
            let raw = serde_json::to_string(&outgoing)?;
            ws_writer.send(Message::Text(raw.into())).await?;
        }
        Result::<()>::Ok(())
    });

    let auth_msg = ws_reader
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("client disconnected before auth"))??;
    let auth = parse_client_message(auth_msg)?;
    let client_name = match auth {
        ClientMessage::Auth { password, name } => {
            if password != args.password {
                let _ = server_tx.send(ServerMessage::AuthError {
                    reason: "invalid password".to_string(),
                });
                remove_client(&state, client_id).await;
                return Ok(());
            }
            let trimmed = name.trim();
            if trimmed.is_empty() {
                let _ = server_tx.send(ServerMessage::AuthError {
                    reason: "name must not be empty".to_string(),
                });
                remove_client(&state, client_id).await;
                return Ok(());
            }
            trimmed.to_string()
        }
        _ => {
            let _ = server_tx.send(ServerMessage::AuthError {
                reason: "expected auth as first message".to_string(),
            });
            remove_client(&state, client_id).await;
            return Ok(());
        }
    };

    let _ = server_tx.send(ServerMessage::AuthOk);

    let current = ensure_client_entry(&state, &args.data_dir, &client_name).await?;
    let snapshot = snapshot_counts(&state).await;
    let _ = server_tx.send(ServerMessage::All { counts: snapshot });
    broadcast_except(
        &state,
        client_id,
        &ServerMessage::Update {
            name: client_name.clone(),
            count: current,
        },
    )
    .await;

    while let Some(incoming) = ws_reader.next().await {
        let msg = incoming?;
        let parsed = parse_client_message(msg)?;
        match parsed {
            ClientMessage::Auth { .. } => {}
            ClientMessage::Update { count } => {
                set_count(&state, &args.data_dir, &client_name, count).await?;
                broadcast_except(
                    &state,
                    client_id,
                    &ServerMessage::Update {
                        name: client_name.clone(),
                        count,
                    },
                )
                .await;
            }
            ClientMessage::RequestAll => {
                let snapshot = snapshot_counts(&state).await;
                let _ = server_tx.send(ServerMessage::All { counts: snapshot });
            }
        }
    }

    remove_client(&state, client_id).await;
    writer_task.abort();
    Ok(())
}

fn parse_client_message(msg: Message) -> Result<ClientMessage> {
    let raw = match msg {
        Message::Text(text) => text,
        Message::Binary(bin) => String::from_utf8(bin.to_vec())?.into(),
        Message::Close(_) => return Err(anyhow::anyhow!("connection closed")),
        _ => return Err(anyhow::anyhow!("unsupported websocket frame")),
    };

    let parsed = serde_json::from_str::<ClientMessage>(&raw).context("invalid client json")?;
    Ok(parsed)
}

async fn ensure_client_entry(state: &Arc<State>, data_dir: &Path, name: &str) -> Result<u64> {
    let mut counts = state.counts.write().await;
    let count = *counts.entry(name.to_string()).or_insert(0);
    write_count_file(data_dir, name, count).await?;
    Ok(count)
}

async fn set_count(state: &Arc<State>, data_dir: &Path, name: &str, count: u64) -> Result<()> {
    {
        let mut counts = state.counts.write().await;
        counts.insert(name.to_string(), count);
    }
    write_count_file(data_dir, name, count).await?;
    Ok(())
}

async fn snapshot_counts(state: &Arc<State>) -> BTreeMap<String, u64> {
    let counts = state.counts.read().await;
    counts
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect::<BTreeMap<_, _>>()
}

async fn broadcast_except(state: &Arc<State>, sender_id: u64, msg: &ServerMessage) {
    let clients = {
        let clients = state.clients.read().await;
        clients.clone()
    };
    for client in clients {
        if client.id != sender_id {
            let _ = client.tx.send(msg.clone());
        }
    }
}

async fn remove_client(state: &Arc<State>, id: u64) {
    let mut clients = state.clients.write().await;
    clients.retain(|c| c.id != id);
}

async fn load_counts(dir: &Path) -> Result<HashMap<String, u64>> {
    let mut counts = HashMap::new();
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.is_empty() {
            continue;
        }
        let content = fs::read_to_string(entry.path()).await?;
        let first_line = content.lines().next().unwrap_or_default().trim();
        if first_line.is_empty() {
            continue;
        }
        if let Ok(count) = first_line.parse::<u64>() {
            counts.insert(name, count);
        }
    }
    Ok(counts)
}

async fn write_count_file(dir: &Path, name: &str, count: u64) -> Result<()> {
    let sanitized = sanitize_name(name);
    let path = dir.join(sanitized);
    let data = format!("{count}\n");
    fs::write(path, data).await?;
    Ok(())
}

fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().max(1));
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('.');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}
