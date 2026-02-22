#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

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

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([430.0, 250.0])
            .with_resizable(false),
        persist_window: false,
        ..Default::default()
    };
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
    address: String,
    port: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            data_dir: "./deaths-server/".to_string(),
            password: String::new(),
            address: "0.0.0.0".to_string(),
            port: "3721".to_string(),
        }
    }
}

struct ServerGuiApp {
    config: ServerConfig,
    status: String,
    child: Option<Child>,
    password_focused: bool,
    address_focused: bool,
}

impl ServerGuiApp {
    fn new() -> Self {
        let config = load_config().unwrap_or_default();
        Self {
            config,
            status: "Stopped".to_string(),
            child: None,
            password_focused: false,
            address_focused: false,
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
        if self.config.address.trim().is_empty() {
            self.status = "Address is required".to_string();
            return;
        }
        if self.config.port.trim().is_empty() {
            self.status = "Port is required".to_string();
            return;
        }
        if self.config.port.parse::<u16>().is_err() {
            self.status = "Port must be a number between 0 and 65535".to_string();
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
            if let Err(err) = save_config(&self.config) {
                self.status = format!("Failed to save config: {err}");
            }
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
                let data_dir_response = ui.text_edit_singleline(&mut self.config.data_dir);
                let data_dir_enter_pressed =
                    data_dir_response.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if data_dir_enter_pressed {
                    data_dir_response.surrender_focus();
                }
                if data_dir_response.changed()
                    && (data_dir_response.lost_focus() || data_dir_enter_pressed)
                {
                    if let Err(err) = save_config(&self.config) {
                        self.status = format!("Failed to save config: {err}");
                    }
                }
                if ui.button("Browse...").clicked() {
                    self.browse_data_dir();
                }
            });
            ui.label("Password");
            let password_response = ui.add(
                egui::TextEdit::singleline(&mut self.config.password)
                    .password(!self.password_focused),
            );
            let password_enter_pressed =
                password_response.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if password_enter_pressed {
                password_response.surrender_focus();
            }
            if password_response.changed()
                && (password_response.lost_focus() || password_enter_pressed)
            {
                if let Err(err) = save_config(&self.config) {
                    self.status = format!("Failed to save config: {err}");
                }
            }
            self.password_focused = password_response.has_focus();
            ui.label("Address");
            let address_response = ui.add(
                egui::TextEdit::singleline(&mut self.config.address)
                    .password(!self.address_focused),
            );
            let address_enter_pressed =
                address_response.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if address_enter_pressed {
                address_response.surrender_focus();
            }
            if address_response.changed()
                && (address_response.lost_focus() || address_enter_pressed)
            {
                if let Err(err) = save_config(&self.config) {
                    self.status = format!("Failed to save config: {err}");
                }
            }
            self.address_focused = address_response.has_focus();
            ui.label("Port");
            let port_response = ui.text_edit_singleline(&mut self.config.port);
            let port_enter_pressed =
                port_response.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if port_enter_pressed {
                port_response.surrender_focus();
            }
            if port_response.changed() && (port_response.lost_focus() || port_enter_pressed) {
                if let Err(err) = save_config(&self.config) {
                    self.status = format!("Failed to save config: {err}");
                }
            }

            ui.horizontal(|ui| {
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
    let bind = compose_bind(config);
    cmd.arg("--data-dir")
        .arg(&config.data_dir)
        .arg("--password")
        .arg(&config.password)
        .arg("--bind")
        .arg(bind)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
}

fn compose_bind(config: &ServerConfig) -> String {
    format!("{}:{}", config.address.trim(), config.port.trim())
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
