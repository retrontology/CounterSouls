# CounterSouls

CounterSouls keeps death counters synced between multiple people.

Use case: one host runs the server, and each player runs the client. Everyone's counter stays updated automatically.

## Download

Get the apps from the GitHub Releases page:
https://github.com/retrontology/countersouls/releases

Latest release:
https://github.com/retrontology/countersouls/releases/latest

You only need the GUI apps for normal setup:

- **Host PC**: `countersouls-server-gui`
- **Each player PC** (including the host player if they are also playing): `countersouls-client`

## Quick Start

Only one host app (server) should be running for the group.
Every player still needs their own client app, including the person hosting if they are also playing on that same PC.

### 1) Host: start the server

Use **Server GUI** (`countersouls-server-gui`) and set:

- **Password**: shared secret (everyone must use the same one)
- **Bind**: usually `0.0.0.0:3721`
- **Data Dir**: folder for saved counters

Then click **Start Server**.

If players are connecting from outside your home network, set up port forwarding on your router.
Default port is **3721** (forward TCP `3721` to the host PC running the server).

### 2) Each player: start the client

Open **Client GUI** (`countersouls-client`) and fill in:

- **Name**: your unique name (example: `nina`)
- **Input File**: text file with your death count (single number on first line, like `12`)
- **Server Address**: host IP + port (example: `192.168.1.10:3721`)
- **Password**: same password as server
- **Output Dir**: folder where other players' counters are written

Click **Save Config**, then **Connect**.

If it connects successfully, your counter and everyone else's counters will sync.

## How to set up the input file (important)

This is designed to work with the **Death Counter for OBS** mod for Elden Ring:
https://www.nexusmods.com/eldenring/mods/2989

Set your `Input File` to the death count file that mod writes, or to any plain text file in the same format.
That file is expected to be updated automatically by the mod.

- First line must be only a number
- Example valid file content:

```text
27
```

## Show counters in OBS

After CounterSouls is connected, set up each counter in OBS:
The counter files are in the folder you selected as `Output Dir` in the client GUI.

1. Create **Text (GDI+)** in your OBS scene.
2. In **Text (GDI+) Properties**, enable **Read from file** and select the counter file (for example `bob.txt`).

Repeat this for each counter you want on screen, using the matching file for that counter.

## Troubleshooting

- **"Auth error"**: password does not match the server
- **Can't connect**: check server address, port (`3721` by default), and firewall/router settings
- **No updates**: make sure input file exists and has a valid number on line 1
- **Counters look shared or jump around**: two clients are using the same `Name`; use unique names if you want separate counters

## Optional: Server CLI

Most users should use the server GUI.
If you prefer command-line hosting, you can run `countersouls-server` from a terminal instead.

Available flags:

- `--password <VALUE>` (required): shared password clients must use
- `--bind <HOST:PORT>` (optional, default: `0.0.0.0:3721`)
- `--data-dir <PATH>` (optional, default: `./deaths-server/`)

Example:

```bash
countersouls-server --password "change-me" --bind "0.0.0.0:3721" --data-dir "./deaths-server/"
```
