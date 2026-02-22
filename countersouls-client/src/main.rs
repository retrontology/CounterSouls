use std::{
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
    time::Duration,
};

use anyhow::{Context, Result};
use countersouls_protocol::{ClientMessage, ServerMessage};
use directories::ProjectDirs;
use eframe::egui;
use futures_util::{SinkExt, StreamExt};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc as tokio_mpsc, time::interval};
use tokio_tungstenite::{connect_async, tungstenite::Message};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "CounterSouls Client",
        options,
        Box::new(|_cc| Ok(Box::new(ClientApp::new()))),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientConfig {
    name: String,
    input_file: String,
    server_addr: String,
    password: String,
    output_dir: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            input_file: String::new(),
            server_addr: "127.0.0.1:3721".to_string(),
            password: String::new(),
            output_dir: "./deaths/".to_string(),
        }
    }
}

#[derive(Debug)]
enum WorkerCommand {
    Disconnect,
    Refresh,
}

#[derive(Debug)]
enum WorkerEvent {
    Connected(bool),
    Status(String),
    OwnCount(u64),
    Error(String),
}

struct ClientApp {
    config: ClientConfig,
    status: String,
    connected: bool,
    own_count: u64,
    event_rx: mpsc::Receiver<WorkerEvent>,
    event_tx: mpsc::Sender<WorkerEvent>,
    command_tx: Option<tokio_mpsc::UnboundedSender<WorkerCommand>>,
}

impl ClientApp {
    fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let config = load_config().unwrap_or_default();
        Self {
            config,
            status: "Disconnected".to_string(),
            connected: false,
            own_count: 0,
            event_rx,
            event_tx,
            command_tx: None,
        }
    }

    fn connect(&mut self) {
        if self.connected || self.command_tx.is_some() {
            return;
        }
        let cfg = self.config.clone();
        let event_tx = self.event_tx.clone();
        let (cmd_tx, cmd_rx) = tokio_mpsc::unbounded_channel();
        self.command_tx = Some(cmd_tx);
        self.status = "Connecting...".to_string();

        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = event_tx.send(WorkerEvent::Error(format!("runtime error: {err}")));
                    return;
                }
            };

            let result = runtime.block_on(run_connection(cfg, cmd_rx, event_tx.clone()));
            if let Err(err) = result {
                let _ = event_tx.send(WorkerEvent::Error(format!("{err:#}")));
            }
            let _ = event_tx.send(WorkerEvent::Connected(false));
            let _ = event_tx.send(WorkerEvent::Status("Disconnected".to_string()));
        });
    }

    fn disconnect(&mut self) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(WorkerCommand::Disconnect);
        }
        self.command_tx = None;
    }

    fn refresh(&mut self) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(WorkerCommand::Refresh);
        }
    }
}

impl Drop for ClientApp {
    fn drop(&mut self) {
        self.disconnect();
    }
}

impl eframe::App for ClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                WorkerEvent::Connected(value) => {
                    self.connected = value;
                    if !value {
                        self.command_tx = None;
                    }
                }
                WorkerEvent::Status(value) => self.status = value,
                WorkerEvent::OwnCount(value) => self.own_count = value,
                WorkerEvent::Error(value) => self.status = format!("Error: {value}"),
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("CounterSouls Client");
            ui.label(format!("Connection: {}", self.status));
            ui.label(format!("My death count: {}", self.own_count));
            ui.separator();

            ui.label("Name");
            ui.text_edit_singleline(&mut self.config.name);
            ui.label("Death count input file (read-only watched file)");
            ui.text_edit_singleline(&mut self.config.input_file);
            ui.label("Server address and port");
            ui.text_edit_singleline(&mut self.config.server_addr);
            ui.label("Password");
            ui.add(egui::TextEdit::singleline(&mut self.config.password).password(true));
            ui.label("Directory for other clients' death files");
            ui.text_edit_singleline(&mut self.config.output_dir);

            ui.horizontal(|ui| {
                if ui.button("Save Config").clicked() {
                    if let Err(err) = save_config(&self.config) {
                        self.status = format!("Error saving config: {err}");
                    } else {
                        self.status = "Config saved".to_string();
                    }
                }

                if !self.connected {
                    if ui.button("Connect").clicked() {
                        self.connect();
                    }
                } else {
                    if ui.button("Disconnect").clicked() {
                        self.disconnect();
                    }
                    if ui.button("Refresh").clicked() {
                        self.refresh();
                    }
                }
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

async fn run_connection(
    config: ClientConfig,
    mut cmd_rx: tokio_mpsc::UnboundedReceiver<WorkerCommand>,
    event_tx: mpsc::Sender<WorkerEvent>,
) -> Result<()> {
    fs::create_dir_all(&config.output_dir)
        .with_context(|| format!("failed to create output dir {}", config.output_dir))?;

    let ws_url =
        if config.server_addr.starts_with("ws://") || config.server_addr.starts_with("wss://") {
            config.server_addr.clone()
        } else {
            format!("ws://{}", config.server_addr)
        };

    let (ws_stream, _) = connect_async(&ws_url)
        .await
        .with_context(|| format!("failed to connect to {ws_url}"))?;
    let (mut ws_writer, mut ws_reader) = ws_stream.split();

    send_client_message(
        &mut ws_writer,
        &ClientMessage::Auth {
            password: config.password.clone(),
            name: config.name.clone(),
        },
    )
    .await?;

    let auth_frame = ws_reader
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("server disconnected during auth"))??;
    let auth_msg = parse_server_message(auth_frame)?;
    match auth_msg {
        ServerMessage::AuthOk => {}
        ServerMessage::AuthError { reason } => {
            return Err(anyhow::anyhow!("auth failed: {reason}"));
        }
        _ => return Err(anyhow::anyhow!("unexpected server response during auth")),
    }

    let _ = event_tx.send(WorkerEvent::Connected(true));
    let _ = event_tx.send(WorkerEvent::Status("Connected".to_string()));

    let initial = read_single_line_count(Path::new(&config.input_file))?;
    let _ = event_tx.send(WorkerEvent::OwnCount(initial));
    send_client_message(&mut ws_writer, &ClientMessage::Update { count: initial }).await?;
    send_client_message(&mut ws_writer, &ClientMessage::RequestAll).await?;

    let (watch_tx, watch_rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = watch_tx.send(res);
        },
        notify::Config::default(),
    )?;
    watcher.watch(Path::new(&config.input_file), RecursiveMode::NonRecursive)?;

    let mut tick = interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            maybe_cmd = cmd_rx.recv() => {
                match maybe_cmd {
                    Some(WorkerCommand::Disconnect) | None => break,
                    Some(WorkerCommand::Refresh) => {
                        let count = read_single_line_count(Path::new(&config.input_file))?;
                        let _ = event_tx.send(WorkerEvent::OwnCount(count));
                        send_client_message(&mut ws_writer, &ClientMessage::Update { count }).await?;
                        send_client_message(&mut ws_writer, &ClientMessage::RequestAll).await?;
                    }
                }
            }
            maybe_frame = ws_reader.next() => {
                let frame = match maybe_frame {
                    Some(frame) => frame?,
                    None => break,
                };
                match parse_server_message(frame)? {
                    ServerMessage::AuthOk => {}
                    ServerMessage::AuthError { reason } => return Err(anyhow::anyhow!("auth error: {reason}")),
                    ServerMessage::All { counts } => {
                        for (name, count) in counts {
                            if name == config.name {
                                continue;
                            }
                            write_count_file(Path::new(&config.output_dir), &name, count)?;
                        }
                    }
                    ServerMessage::Update { name, count } => {
                        if name != config.name {
                            write_count_file(Path::new(&config.output_dir), &name, count)?;
                        }
                    }
                }
            }
            _ = tick.tick() => {
                while let Ok(event_result) = watch_rx.try_recv() {
                    let event = match event_result {
                        Ok(event) => event,
                        Err(err) => {
                            let _ = event_tx.send(WorkerEvent::Error(format!("watcher error: {err}")));
                            continue;
                        }
                    };
                    if !event.paths.iter().any(|p| p == Path::new(&config.input_file)) {
                        continue;
                    }
                    let count = match read_single_line_count(Path::new(&config.input_file)) {
                        Ok(count) => count,
                        Err(err) => {
                            let _ = event_tx.send(WorkerEvent::Error(format!("failed to read input count: {err}")));
                            continue;
                        }
                    };
                    let _ = event_tx.send(WorkerEvent::OwnCount(count));
                    send_client_message(&mut ws_writer, &ClientMessage::Update { count }).await?;
                }
            }
        }
    }

    Ok(())
}

async fn send_client_message<S>(writer: &mut S, msg: &ClientMessage) -> Result<()>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let raw = serde_json::to_string(msg)?;
    writer.send(Message::Text(raw.into())).await?;
    Ok(())
}

fn parse_server_message(msg: Message) -> Result<ServerMessage> {
    let raw = match msg {
        Message::Text(text) => text.to_string(),
        Message::Binary(bin) => String::from_utf8(bin.to_vec())?,
        Message::Close(_) => return Err(anyhow::anyhow!("connection closed")),
        _ => return Err(anyhow::anyhow!("unsupported websocket frame")),
    };
    Ok(serde_json::from_str::<ServerMessage>(&raw)?)
}

fn read_single_line_count(path: &Path) -> Result<u64> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read input file {}", path.display()))?;
    let first = content.lines().next().unwrap_or_default().trim();
    if first.is_empty() {
        return Err(anyhow::anyhow!("input file has empty first line"));
    }
    let count = first
        .parse::<u64>()
        .with_context(|| format!("invalid integer in {}", path.display()))?;
    Ok(count)
}

fn write_count_file(dir: &Path, name: &str, count: u64) -> Result<()> {
    fs::create_dir_all(dir)?;
    let file_name = sanitize_name(name);
    let path = dir.join(file_name);
    fs::write(path, format!("{count}\n"))?;
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

fn config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "countersouls", "client")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve config directory"))?;
    fs::create_dir_all(dirs.config_dir())?;
    Ok(dirs.config_dir().join("config.json"))
}

fn load_config() -> Result<ClientConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(ClientConfig::default());
    }
    let raw = fs::read_to_string(&path)?;
    let parsed = serde_json::from_str::<ClientConfig>(&raw)?;
    Ok(parsed)
}

fn save_config(config: &ClientConfig) -> Result<()> {
    let path = config_path()?;
    let raw = serde_json::to_string_pretty(config)?;
    fs::write(path, raw)?;
    Ok(())
}
