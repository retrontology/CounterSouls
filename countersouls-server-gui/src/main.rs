use std::{
    fs,
    io::ErrorKind,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use eframe::egui;
use rfd::FileDialog;
use serde::{Deserialize, Serialize};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "CounterSouls Server GUI",
        options,
        Box::new(|_cc| Ok(Box::new(ServerGuiApp::new()))),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerConfig {
    data_dir: String,
    password: String,
    bind: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            data_dir: "./deaths-server/".to_string(),
            password: String::new(),
            bind: "0.0.0.0:3721".to_string(),
        }
    }
}

struct ServerGuiApp {
    config: ServerConfig,
    status: String,
    child: Option<Child>,
    password_focused: bool,
    bind_focused: bool,
}

impl ServerGuiApp {
    fn new() -> Self {
        Self {
            config: load_config().unwrap_or_default(),
            status: "Stopped".to_string(),
            child: None,
            password_focused: false,
            bind_focused: false,
        }
    }

    fn start_server(&mut self) {
        if self.child.is_some() {
            return;
        }
        if self.config.password.trim().is_empty() {
            self.status = "Password is required".to_string();
            return;
        }

        let mut cmd = Command::new(server_binary_name());
        configure_server_command(&mut cmd, &self.config);

        match cmd.spawn() {
            Ok(child) => {
                self.child = Some(child);
                self.status = "Running".to_string();
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                let Some(fallback_path) = sibling_server_binary_path() else {
                    self.status = format!(
                        "Failed to start server: {err}. Not found in PATH, and failed to resolve GUI executable directory"
                    );
                    return;
                };
                if !fallback_path.exists() {
                    self.status = format!(
                        "Failed to start server: {err}. Not found in PATH or next to GUI ({})",
                        fallback_path.display()
                    );
                    return;
                }

                let mut fallback_cmd = Command::new(&fallback_path);
                configure_server_command(&mut fallback_cmd, &self.config);
                match fallback_cmd.spawn() {
                    Ok(child) => {
                        self.child = Some(child);
                        self.status = "Running".to_string();
                    }
                    Err(fallback_err) => {
                        self.status = format!(
                            "Failed to start server from {}: {fallback_err}",
                            fallback_path.display()
                        );
                    }
                }
            }
            Err(err) => {
                self.status = format!("Failed to start server: {err}");
            }
        }
    }

    fn stop_server(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
        }
        self.status = "Stopped".to_string();
    }

    fn browse_data_dir(&mut self) {
        if let Some(path) = FileDialog::new().pick_folder() {
            self.config.data_dir = path.display().to_string();
        }
    }
}

impl Drop for ServerGuiApp {
    fn drop(&mut self) {
        self.stop_server();
    }
}

impl eframe::App for ServerGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("CounterSouls Server");
            ui.label(format!("Status: {}", self.status));
            ui.separator();

            ui.label("Data directory");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.config.data_dir);
                if ui.button("Browse...").clicked() {
                    self.browse_data_dir();
                }
            });
            ui.label("Password");
            let password_response = ui.add(
                egui::TextEdit::singleline(&mut self.config.password)
                    .password(!self.password_focused),
            );
            self.password_focused = password_response.has_focus();
            ui.label("Bind address and port");
            let bind_response = ui.add(
                egui::TextEdit::singleline(&mut self.config.bind).password(!self.bind_focused),
            );
            self.bind_focused = bind_response.has_focus();

            ui.horizontal(|ui| {
                if ui.button("Save Config").clicked() {
                    match save_config(&self.config) {
                        Ok(()) => self.status = "Config saved".to_string(),
                        Err(err) => self.status = format!("Failed to save config: {err}"),
                    }
                }

                if self.child.is_none() {
                    if ui.button("Start Server").clicked() {
                        self.start_server();
                    }
                } else if ui.button("Stop Server").clicked() {
                    self.stop_server();
                }
            });
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(250));
    }
}

fn server_binary_name() -> &'static str {
    if cfg!(windows) {
        "countersouls-server.exe"
    } else {
        "countersouls-server"
    }
}

fn sibling_server_binary_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(server_binary_name()))
}

fn configure_server_command(cmd: &mut Command, config: &ServerConfig) {
    cmd.arg("--data-dir")
        .arg(&config.data_dir)
        .arg("--password")
        .arg(&config.password)
        .arg("--bind")
        .arg(&config.bind)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

fn config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "countersouls", "server-gui")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve config directory"))?;
    fs::create_dir_all(dirs.config_dir())?;
    Ok(dirs.config_dir().join("config.json"))
}

fn load_config() -> Result<ServerConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(ServerConfig::default());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_str::<ServerConfig>(&raw)?)
}

fn save_config(config: &ServerConfig) -> Result<()> {
    let path = config_path()?;
    let raw = serde_json::to_string_pretty(config)?;
    fs::write(&path, raw).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
