# SocketFileShare

SocketFileShare is a simple socket-based file sharing tool.
It runs a Python TCP server and a Python client so you can upload, download, and manage files over the network.
The project also logs basic performance metrics for transfers.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. Start the server

```bash
python main.py
```

* Choose option `1` (Server).
* On first run, you'll be prompted to create an admin account.
* Enter the IP and port you want the server to bind to.

### 2. Set up the client key (one-time per client machine)

After the server's first run, it generates a shared key and also writes a client-ready copy:

* On the **server** machine, the server uses:
  `server/storage/database/auth_secret.key`
* A matching copy for the client lives at:
  `client/storage/database/auth_secret.key`

To deploy the client to another machine, copy the entire `client/` folder from the server system to the new host.
If you already have a client tree on the target machine, at minimum copy:

*from server host* `client/storage/database/auth_secret.key`
*to client host*   `client/storage/database/auth_secret.key`

Treat this file like a secret; anyone with it can authenticate as a client.

### 3. Start the client

On the client machine:

```bash
python main.py
```

* Choose option `2` (Client).
* Enter the server IP and port.
* Log in with your username and password.

### 4. Client commands

From the client prompt, type `help` to see all available commands, including:

* File operations: `upload`, `download`, `delete`, `dir`, `subfolder`
* Account: `passwd`, `logout`
* Admin-only commands (when logged in as admin)
* Session control: `quit`, `exit`

**File path behavior**

* `upload <local_path> [remote]`

  * If `<local_path>` contains a path (e.g. `some/folder/file.mp4`), it’s used directly.
  * If it’s just a filename (e.g. `Cat.mp4`), the client searches:

    * the current working directory (project root when running `main.py`)
    * `client/storage/ID_<user_id>_<username>/`
  * If the same filename exists in multiple locations, the client asks which one to use.
  * If the remote file already exists, the client asks before overwriting.

* `download <remote> [local_name]`

  * All downloads go to `client/downloads/`.
  * If `[local_name]` is provided, its basename becomes the filename in `client/downloads/`.
  * If the target file already exists, the client asks before overwriting.

### Client storage layout

Everything client-side lives under `client/`:

* `client/storage/database/auth_secret.key` – shared Fernet auth key
* `client/storage/ID_<user_id>_<username>/` – per-user storage (optional local copies, metrics)
* `client/downloads/` – all downloaded files

You can move/copy `client/` as a self-contained client bundle.

## Features

* Multithreaded TCP server (multiple clients at once)
* Encrypted authentication with shared Fernet key
* Per-user storage directories and path safety checks
* Basic file operations (upload/download/list/delete/subfolders)
* Admin user management commands
* Client and server performance metrics (CSV) for transfers

## Project Structure

```text
SocketFileShare/
│
├── analysis/                 # Performance metrics
│   └── performance_eval.py   # Collects transfer times, data rates, response times
│
├── client/                   # Client-side modules
│   ├── client_main.py        # Runs client connection and session
│   └── commands.py           # Processes user input and client commands
│
├── server/                   # Server-side modules
│   ├── auth.py               # Handles login and authentication logic
│   ├── file_ops.py           # File operations (upload, download, dir, etc.)
│   └── server_main.py        # Starts multithreaded server
│
├── .gitignore                # Git ignore rules for project files
├── main.py                   # Unified launcher for server/client selection
├── README.md                 # Project overview, setup, and usage
└── requirements.txt          # Python dependencies
```

Generated at runtime (not tracked in git):

* `server/storage/`: per-user files, user DB, key file, server metrics
* `client/storage/ID_<user_id>_<username>/client_metrics.csv`: per-user client performance metrics
* `client/downloads/`: downloaded files from the server
