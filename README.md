# CounterSouls

Small Rust workspace for synchronizing "death counter" values across clients over WebSockets.

## Workspace layout

- `countersouls-protocol`: shared serde message types used by client and server
- `countersouls-server`: WebSocket server that stores per-player counters
- `countersouls-client`: desktop GUI client that reads a local input count file and syncs with server
- `countersouls-server-gui`: desktop GUI to configure and launch `countersouls-server`

## Requirements

- Rust toolchain (`cargo`, stable)

## Build

```bash
cargo build
```

## Run

### 1) Start the server

```bash
cargo run -p countersouls-server -- \
  --password "change-me" \
  --bind "0.0.0.0:3721" \
  --data-dir "./deaths-server/"
```

Server options:

- `--password` (required): shared secret clients must provide
- `--bind` (optional, default: `0.0.0.0:3721`)
- `--data-dir` (optional, default: `./deaths-server/`)

### 2) Start a client

```bash
cargo run -p countersouls-client
```

In the client UI, fill in:

- `name`: unique player name
- `input_file`: local file that contains a single integer on the first line
- `server_addr`: host:port or full `ws://` URL (default `127.0.0.1:3721`)
- `password`: same value passed to server `--password`
- `output_dir`: where other players' counters are written (default `./deaths/`)

Click **Save Config**, then **Connect**.

### 3) (Optional) Run server with GUI launcher

```bash
cargo run -p countersouls-server-gui
```

The server GUI writes config to the OS app config directory and launches the `countersouls-server` binary with those values.

## Protocol summary

Client messages:

- `auth { password, name }`
- `update { count }`
- `request_all`

Server messages:

- `auth_ok`
- `auth_error { reason }`
- `all { counts }`
- `update { name, count }`

## Test

```bash
cargo test
```
