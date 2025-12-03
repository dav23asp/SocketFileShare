# client/commands.py
# Processes user input and client commands.

import os           # local file paths
import socket       # TCP client socket
import threading    # sync reads and writes
import json         # auth/admin payload encoding
from cryptography.fernet import Fernet                          # encrypt auth and admin payloads
from analysis.performance_eval import PerfRecorder, timed       # client-side metrics

#### Constants ####
BUFFER = 64 * 1024   # 64KB buffer size for file transfer
ENC = "utf-8"        # Encoding format for strings
LINE_END = b"\n"     # Line ending byte sequence

# Base paths for client-side storage and key (all state lives under client/)
BASE_DIR = os.path.dirname(__file__)
CLIENT_STORAGE_ROOT = os.path.join(BASE_DIR, "storage")
CLIENT_DATABASE_DIR = os.path.join(CLIENT_STORAGE_ROOT, "database")
CLIENT_SECRET_KEY_FILE = os.path.join(CLIENT_DATABASE_DIR, "auth_secret.key")

# All downloads are stored under client/downloads/
CLIENT_DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")

#### Encryption helpers ####
def _load_shared_key():
    """
    Load the shared Fernet key used for auth and admin payloads.

    Returns:
        bytes | None: Key bytes if available, otherwise None.
    """
    # Client never generates this key; it must already be on disk.
    if not os.path.exists(CLIENT_SECRET_KEY_FILE):
        print(f"[auth] Shared key file '{CLIENT_SECRET_KEY_FILE}' not found.")
        print("[auth] Copy this key file from the server host into the client/storage/database/ directory.")
        return None

    with open(CLIENT_SECRET_KEY_FILE, "rb") as f:
        key = f.read().strip()

    if not key:
        print("[auth] Shared key file is empty.")
        return None

    return key

def _get_cipher():
    """
    Create a Fernet cipher instance using the shared key.

    Returns:
        Fernet | None: Cipher object, or None if the key cannot be loaded.
    """
    key = _load_shared_key()
    if key is None:
        return None

    try:
        return Fernet(key)
    except Exception as exc:
        print(f"[auth] Could not create cipher: {exc}")
        return None

def encrypt_payload(payload_dict):
    """
    Encrypt a small JSON payload for transit.

    Parameters:
        payload_dict (dict): Data to JSON-encode and encrypt.

    Returns:
        str | None: Base64 token string on success, or None on error.
    """
    cipher = _get_cipher()
    if cipher is None:
        return None

    try:
        # All auth/admin JSON -> bytes -> Fernet token.
        raw = json.dumps(payload_dict).encode(ENC)
        token = cipher.encrypt(raw)
        return token.decode(ENC)
    except Exception as exc:
        print(f"[auth] Encryption failed: {exc}")
        return None

#### Client session ####
class ClientSession:
    """
    High-level client session wrapper for one TCP connection.

    Tracks:
      - Server address (ip, port)
      - Socket object and connection state
      - Authenticated username, user_id, and role
      - Client-side performance metrics
      - Client-side storage paths for metrics
    """

    def __init__(self, ip, port):
        # Target server address
        self.addr = (ip, port)              # Server (ip, port)
        self.sock = None                    # Active socket
        # Locks keep reads/writes from overlapping across threads
        self._recv_lock = threading.Lock()  # Serialize reads
        self._send_lock = threading.Lock()  # Serialize writes
        self.connected = False              # TCP connection flag
        self.username = None                # Authenticated username
        self.user_id = None                 # Server-assigned user id
        self.role = None                    # 'user' or 'admin'
        self.authenticated = False          # Auth status
        self.perf = PerfRecorder()          # Local performance recorder

        # Client-side storage roots (under client/storage/)
        self.client_storage_root = CLIENT_STORAGE_ROOT
        self.user_storage_dir = None        # Filled after first successful auth

    def _init_user_storage_dir(self):
        """
        Create and remember the per-user client storage directory.

        Layout (relative to repo root, when running main.py):
            client/storage/ID_<user_id>_<username>/
        """
        if not self.user_id or not self.username:
            return None

        # Make sure base client storage directory exists.
        os.makedirs(self.client_storage_root, exist_ok=True)

        folder_name = f"ID_{self.user_id}_{self.username}"
        user_dir = os.path.join(self.client_storage_root, folder_name)
        os.makedirs(user_dir, exist_ok=True)
        self.user_storage_dir = user_dir
        return user_dir

    def _resolve_local_upload(self, local_path):
        """
        Resolve which local file to upload.

        Rules:
          - If local_path includes a path separator, treat it as an explicit path.
          - If it's just a filename, search:
              1) current working directory
              2) per-user client storage dir (if it exists)
        If multiple matches are found, prompt the user to choose one.
        """
        # Explicit path: just check and use it.
        if os.sep in local_path or "/" in local_path:
            if os.path.isfile(local_path):
                resolved = os.path.abspath(local_path)
                print(f"[i] Using local file: {resolved}")
                return resolved
            print(f"[x] Local file '{local_path}' not found.")
            return None

        # Bare filename: search in known roots.
        candidates = []

        # 1) Current working directory (project root when running main.py)
        cwd_candidate = os.path.join(os.getcwd(), local_path)
        if os.path.isfile(cwd_candidate):
            candidates.append(cwd_candidate)

        # 2) Per-user client storage directory (client/storage/ID_<id>_<username>/)
        if self.user_storage_dir:
            user_candidate = os.path.join(self.user_storage_dir, local_path)
            if os.path.isfile(user_candidate) and user_candidate not in candidates:
                candidates.append(user_candidate)

        if not candidates:
            print(f"[x] Local file '{local_path}' not found in current directory or client storage.")
            return None

        if len(candidates) == 1:
            resolved = os.path.abspath(candidates[0])
            print(f"[i] Using local file: {resolved}")
            return resolved

        # Multiple matches: ask which one to use.
        print(f"[?] Multiple matches for '{local_path}':")
        for idx, path in enumerate(candidates, start=1):
            print(f"  [{idx}] {path}")

        choice = input(f"Select file to upload [1-{len(candidates)} or 'c' to cancel]: ").strip().lower()
        if choice in ("c", "q", "quit", "cancel"):
            print("[i] Upload cancelled.")
            return None

        try:
            idx = int(choice)
        except ValueError:
            print("[x] Invalid selection; upload cancelled.")
            return None

        if not (1 <= idx <= len(candidates)):
            print("[x] Selection out of range; upload cancelled.")
            return None

        resolved = os.path.abspath(candidates[idx - 1])
        print(f"[i] Using local file: {resolved}")
        return resolved

    def _resolve_download_target(self, remote_name, local_override=None):
        """
        Decide where to store a downloaded file locally.

        All downloads are placed under client/downloads/.
        If local_override is given, only its basename is used.
        """
        if local_override:
            filename = os.path.basename(local_override)
        else:
            filename = os.path.basename(remote_name)

        if not filename:
            filename = "downloaded_file"

        try:
            os.makedirs(CLIENT_DOWNLOADS_DIR, exist_ok=True)
        except OSError as exc:
            print(f"[x] Could not create local downloads directory '{CLIENT_DOWNLOADS_DIR}': {exc}")
            return None

        return os.path.join(CLIENT_DOWNLOADS_DIR, filename)

    #### Basic Helpers ####
    def _sendline(self, line):
        """
        Send a single line to the server, appending a newline.
        """
        if self.sock is None:
            print("[!] No active connection.")
            return
        data = (line.rstrip("\n") + "\n").encode(ENC)
        # Lock so that concurrent commands can't interleave bytes.
        with self._send_lock:
            self.sock.sendall(data)

        # Basic outbound logging for visibility (hide token bodies).
        if line.startswith("AUTH "):
            log_cmd = "AUTH <token>"
        elif line.startswith("PASSWD "):
            log_cmd = "PASSWD <token>"
        elif line.startswith("ADMIN ") and " " in line:
            # Only print the ADMIN subcommand, not the encrypted token
            log_cmd = "ADMIN " + line.split(" ", 2)[1]
        else:
            log_cmd = line
        print(f"[client >>] {log_cmd}")

    def _readline(self):
        """
        Read a single newline-terminated line from the server.

        Returns:
            str | None: Line text without the newline, or None on EOF or timeout.
        """
        if self.sock is None:
            return None

        buf = bytearray()
        # Read one byte at a time so we can stop exactly on '\n'.
        with self._recv_lock:
            while True:
                try:
                    ch = self.sock.recv(1)
                except socket.timeout:
                    # No data within timeout; return None unless we already have some bytes.
                    if not buf:
                        return None
                    break
                if not ch:
                    # Remote closed.
                    break
                buf += ch
                if ch == LINE_END:
                    break

        if not buf:
            return None

        # Strip trailing '\n' and decode.
        return buf[:-1].decode(ENC, errors="replace")

    #### Connection Lifecycle ####
    def connect(self):
        """
        Open a TCP connection to the configured server address.

        Returns:
            bool: True on success, False on failure.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print(f"[+] Connecting to {self.addr[0]}:{self.addr[1]} ...")
            self.sock.connect(self.addr)
            # Short socket timeout for command/response style traffic.
            self.sock.settimeout(5)
            self.connected = True
            print("[i] TCP connection established.\n")
            return True
        except ConnectionRefusedError:
            print(f"[x] Connection refused. No server listening at {self.addr}.")
        except socket.timeout:
            print("[x] Connection timed out.")
        except OSError as e:
            print(f"[x] Connection error: {e}")

        # On any error, tear down any partial state.
        self.close()
        return False

    def logout(self):
        """
        Send a LOGOUT command and close the connection.
        """
        if not self.connected or not self.sock:
            print("[!] Not connected to a server.")
            return
        try:
            self._sendline("LOGOUT")
            resp = self._readline()
            if resp is None:
                print("[i] Logout request sent (no response).")
            else:
                print(f"[server] {resp}")
        except (OSError, socket.error) as e:
            print(f"[x] Error sending logout: {e}")
        finally:
            self.close()

    def close(self):
        """
        Safely close the socket and reset session state.
        """
        if self.sock:
            try:
                self.sock.close()
                print("[i] Connection closed.")
            except Exception:
                pass

        # Try to write out client-side metrics before resetting.
        try:
            # Decide where to write metrics:
            # - If the user has authenticated, use their per-user folder under client/storage/.
            # - If not, fall back to a generic CSV under client/storage/.
            if self.user_storage_dir:
                try:
                    os.makedirs(self.user_storage_dir, exist_ok=True)
                except OSError:
                    # If this fails, fall back to generic storage root.
                    self.user_storage_dir = None

            if self.user_storage_dir:
                metrics_path = os.path.join(self.user_storage_dir, "client_metrics.csv")
            else:
                os.makedirs(self.client_storage_root, exist_ok=True)
                metrics_path = os.path.join(self.client_storage_root, "client_metrics.csv")

            # Single CSV with all timing + transfer metrics for this run.
            self.perf.to_csv(metrics_path)
            print(f"[i] Wrote client performance metrics to {metrics_path}")
        except Exception as exc:
            print(f"[x] Failed to write client performance metrics: {exc}")

        # Reset connection / auth state.
        self.sock = None
        self.connected = False
        self.authenticated = False
        self.username = None
        self.user_id = None
        self.role = None
        # Do not reset user_storage_dir/client_storage_root; those describe local disk layout.

    #### Authentication and account commands ####
    def auth(self, username, password):
        """
        Authenticate with the server using an encrypted AUTH payload.

        Returns:
            bool: True if authentication succeeds, False otherwise.
        """
        if not self.connected or not self.sock:
            print("[!] Not connected; cannot authenticate.")
            return False

        payload = {
            "op": "login",
            "username": username,
            "password": password,
        }

        # Build encrypted Fernet token containing username+password.
        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted auth payload.")
            return False

        timer = timed()
        self._sendline(f"AUTH {token}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="auth", seconds=duration, source="client")

        if resp is None:
            print("[x] No response from server during auth.")
            self.close()
            return False

        parts = resp.split()
        if len(parts) >= 2 and parts[0] == "OK" and parts[1] == "AUTH":
            # Expected format: OK AUTH role=<role> user_id=<user_id>
            role = None
            user_id = None
            for piece in parts[2:]:
                if piece.startswith("role="):
                    role = piece.split("=", 1)[1]
                elif piece.startswith("user_id="):
                    user_id = piece.split("=", 1)[1]

            self.username = username
            self.role = role
            self.user_id = user_id
            self.authenticated = True

            # Create per-user client storage folder now that we know id and username.
            self._init_user_storage_dir()

            print(f"[i] Authenticated as '{self.username}' (role={self.role}, id={self.user_id}).")
            return True

        # Server error path.
        if len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "AUTH":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] Authentication failed: {reason}")
        else:
            print(f"[x] Unexpected auth response: {resp}")

        self.close()
        return False

    def change_password(self, old_password, new_password):
        """
        Change the current user's password via the PASSWD command.
        """
        if not self.authenticated:
            print("[!] You must authenticate before changing password.")
            return

        payload = {
            "op": "passwd",
            "old_password": old_password,
            "new_password": new_password,
        }

        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted password payload.")
            return

        timer = timed()
        self._sendline(f"PASSWD {token}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="passwd", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for PASSWD command.")
            return

        parts = resp.split()
        if len(parts) >= 2 and parts[0] == "OK" and parts[1] == "PASSWD":
            print("[i] Password changed.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "PASSWD":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] PASSWD failed: {reason}")
        else:
            print(f"[x] Unexpected PASSWD response: {resp}")

    #### Admin commands ####
    def _check_admin(self, cmd_name):
        """
        Verify that the current session is authenticated as an admin.

        Returns:
            bool: True if the admin command is allowed, False otherwise.
        """
        if self.role != "admin":
            print(f"[!] {cmd_name} denied: not logged in as admin.")
            return False
        if not self.authenticated:
            print(f"[!] {cmd_name} denied: not authenticated.")
            return False
        return True

    def admin_adduser(self, username, role, password):
        """
        Send an ADMIN ADDUSER command to create a new user.
        """
        if not self._check_admin("ADMIN ADDUSER"):
            return

        # Password is passed inside encrypted token, not in plaintext line.
        payload = {
            "op": "adduser",
            "password": password,
        }
        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted ADDUSER payload.")
            return

        line = f"ADMIN ADDUSER {username} {role} {token}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_adduser", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN ADDUSER.")
            return

        parts = resp.split()
        if len(parts) >= 3 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "ADDUSER":
            print(f"[i] Added user '{username}' with role '{role}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN ADDUSER failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN ADDUSER response: {resp}")

    def admin_deluser(self, username):
        """
        Send an ADMIN DELUSER command to remove a user.
        """
        if not self._check_admin("ADMIN DELUSER"):
            return

        line = f"ADMIN DELUSER {username}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_deluser", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN DELUSER.")
            return

        parts = resp.split()
        if len(parts) >= 3 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "DELUSER":
            print(f"[i] Deleted user '{username}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN DELUSER failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN DELUSER response: {resp}")

    def admin_setrole(self, username, role):
        """
        Send an ADMIN SETROLE command to change a user's role.
        """
        if not self._check_admin("ADMIN SETROLE"):
            return

        line = f"ADMIN SETROLE {username} {role}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_setrole", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN SETROLE.")
            return

        parts = resp.split()
        if len(parts) >= 4 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "SETROLE":
            print(f"[i] Set role for '{username}' to '{role}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN SETROLE failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN SETROLE response: {resp}")

    def admin_resetpass(self, username, new_password):
        """
        Send an ADMIN RESETPASS command to set a new password for a user.
        """
        if not self._check_admin("ADMIN RESETPASS"):
            return

        payload = {
            "op": "resetpass",
            "new_password": new_password,
        }
        token = encrypt_payload(payload)
        if token is None:
            print("[x] Could not build encrypted RESETPASS payload.")
            return

        line = f"ADMIN RESETPASS {username} {token}"
        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_resetpass", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for ADMIN RESETPASS.")
            return

        parts = resp.split()
        if len(parts) >= 3 and parts[0] == "OK" and parts[1] == "ADMIN" and parts[2] == "RESETPASS":
            print(f"[i] Reset password for '{username}'.")
        elif len(parts) >= 2 and parts[0] == "ERR" and parts[1] == "ADMIN":
            reason = " ".join(parts[2:]) if len(parts) > 2 else "unknown error"
            print(f"[x] ADMIN RESETPASS failed: {reason}")
        else:
            print(f"[x] Unexpected ADMIN RESETPASS response: {resp}")

    def admin_listusers(self):
        """
        Send an ADMIN LISTUSERS command and print the returned user list.
        """
        if not self._check_admin("ADMIN LISTUSERS"):
            return

        timer = timed()
        self._sendline("ADMIN LISTUSERS")
        first_line = self._readline()
        duration = timer()
        self.perf.record_response(operation="admin_listusers", seconds=duration, source="client")

        if first_line is None:
            print("[x] No response for ADMIN LISTUSERS.")
            return

        if first_line.strip() != "OK ADMIN LISTUSERS BEGIN":
            print(f"[x] Unexpected response: {first_line}")
            return

        print("[i] Users:")
        while True:
            line = self._readline()
            if line is None:
                print("[x] ADMIN LISTUSERS ended unexpectedly.")
                return
            if line.strip() == "OK ADMIN LISTUSERS END":
                break
            # Each line: "<username> <role> <user_id>"
            print(f"  {line}")

    #### File and directory commands ####
    def dir_list(self, path=None):
        """
        Request a directory listing from the server via the DIR command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using DIR.")
            return

        # Empty path or "." means root of user's remote storage.
        if path is None or path == ".":
            line = "DIR"
        else:
            line = f"DIR {path}"

        timer = timed()
        self._sendline(line)
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="dir", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for DIR.")
            return

        if resp.startswith("ERR"):
            print(f"[server] {resp}")
            return

        # Multi-line listing framed by BEGIN/END from server.
        if resp == "BEGIN":
            print("Directory listing:")
            while True:
                line = self._readline()
                if line is None:
                    print("[x] Server closed connection unexpectedly.")
                    break
                if line.strip() == "END":
                    break
                print(f"  {line}")
        else:
            print(f"[server] {resp}")

    def delete(self, remote_path):
        """
        Request deletion of a remote file via the DELETE command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using DELETE.")
            return

        timer = timed()
        self._sendline(f"DELETE {remote_path}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="delete", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for DELETE.")
            return
        print(f"[server] {resp}")

    def subfolder(self, action, path):
        """
        Manage remote subfolders using the SUBFOLDER command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using SUBFOLDER.")
            return

        action = action.lower()
        if action not in ("create", "delete"):
            print("[x] SUBFOLDER action must be 'create' or 'delete'.")
            return

        timer = timed()
        self._sendline(f"SUBFOLDER {action} {path}")
        resp = self._readline()
        duration = timer()
        self.perf.record_response(operation="subfolder", seconds=duration, source="client")

        if resp is None:
            print("[x] No response for SUBFOLDER.")
            return
        print(f"[server] {resp}")

    def upload(self, local_path, remote_name=None):
        """
        Request an upload of a local file to the server via the UPLOAD command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using UPLOAD.")
            return

        if not self.connected or self.sock is None:
            print("[!] Not connected; cannot upload.")
            return

        # Resolve which local file to use (handles duplicates & prompts).
        resolved_local = self._resolve_local_upload(local_path)
        if resolved_local is None:
            return

        filename = remote_name if remote_name else os.path.basename(resolved_local)
        file_size = os.path.getsize(resolved_local)

        # Protocol: UPLOAD <filename> <size>
        print(f"[i] Requesting upload: {filename} ({file_size} bytes)...")
        self._sendline(f"UPLOAD {filename} {file_size}")

        # Handshake: may see READY or EXISTS UPLOAD <path> or ERR ...
        try:
            resp = self._readline()
            if resp is None:
                print("[x] Connection closed by server during handshake.")
                return

            # Optional overwrite negotiation (if server implements it).
            if resp.startswith("EXISTS UPLOAD"):
                print(f"[server] {resp}")
                choice = input("File exists on server. Overwrite? [y/N]: ").strip().lower()
                if choice not in ("y", "yes"):
                    self._sendline("SKIP")
                    final = self._readline()
                    if final is not None:
                        print(f"[server] {final}")
                    else:
                        print("[x] No response after SKIP.")
                    return

                self._sendline("OVERWRITE")
                resp = self._readline()
                if resp is None:
                    print("[x] No response after OVERWRITE.")
                    return

            # At this point we expect READY.
            if resp == "READY":
                pass
            else:
                if resp.startswith("ERR"):
                    print(f"[x] Server rejected upload request. Reason: {resp}")
                else:
                    print(f"[x] Unexpected upload response: {resp}")
                return

        except Exception as e:
            print(f"[x] Error during handshake: {e}")
            return

        # Start data transfer loop: stream file contents in BUFFER chunks.
        print("[i] Sending file data...")
        timer = timed()
        sent_bytes = 0

        try:
            with open(resolved_local, "rb") as f:
                while True:
                    chunk = f.read(BUFFER)
                    if not chunk:
                        break
                    with self._send_lock:
                        self.sock.sendall(chunk)
                    sent_bytes += len(chunk)

            duration = timer()
            self.perf.record_transfer(
                operation="upload",
                bytes_count=sent_bytes,
                seconds=duration,
                source="client",
            )

            if sent_bytes != file_size:
                print(f"[!] Warning: File size changed during upload. Sent {sent_bytes}/{file_size}.")

            # Wait for final ACK from server.
            final_resp = self._readline()
            if final_resp and final_resp.startswith("OK"):
                print(f"[i] Upload complete. Server response: {final_resp}")
            else:
                print(f"[x] Upload may have failed. Server response: {final_resp}")
        except OSError as e:
            print(f"[x] Network error during transmission: {e}")
            self.close()
        except Exception as e:
            print(f"[x] Unexpected error: {e}")

    def download(self, remote_name, local_path=None):
        """
        Request a download of a remote file from the server via the DOWNLOAD command.
        """
        if not self.authenticated:
            print("[!] Authenticate before using DOWNLOAD.")
            return

        if not self.connected or self.sock is None:
            print("[!] Not connected; cannot download.")
            return

        timer = timed()
        self._sendline(f"DOWNLOAD {remote_name}")
        resp = self._readline()

        if resp is None:
            print("[x] No response for DOWNLOAD.")
            return

        parts = resp.split()
        if len(parts) != 2 or parts[0] != "SIZE":
            print(f"[x] Server rejected download. Response: {resp}")
            return

        try:
            file_size = int(parts[1])
        except ValueError:
            print(f"[x] Invalid file size received: {parts[1]}")
            return

        # Decide where to save the file locally (always under client/downloads/)
        local_target = self._resolve_download_target(remote_name, local_path)
        if local_target is None:
            # Cannot create downloads directory; politely decline.
            self._sendline("SKIP")
            return

        print(f"[i] Receiving '{remote_name}' ({file_size} bytes) to '{local_target}'...")

        # If the file already exists, confirm overwrite.
        if os.path.exists(local_target):
            choice = input(f"[?] Local file '{local_target}' already exists. Overwrite? [y/N]: ").strip().lower()
            if choice not in ("y", "yes"):
                print("[i] Download cancelled; existing file left untouched.")
                # Tell server we're not going to receive this file.
                self._sendline("SKIP")
                return

        # Tell server we are ready to receive the bytes.
        self._sendline("READY")

        received_bytes = 0

        try:
            with open(local_target, "wb") as f:
                while received_bytes < file_size:
                    to_read = min(BUFFER, file_size - received_bytes)
                    chunk = self.sock.recv(to_read)
                    if not chunk:
                        print("[x] Connection closed by server mid-transfer.")
                        break
                    f.write(chunk)
                    received_bytes += len(chunk)

            duration = timer()
            self.perf.record_transfer(
                operation="download",
                bytes_count=received_bytes,
                seconds=duration,
                source="client",
            )

            if received_bytes == file_size:
                print(f"[i] Download complete: {received_bytes} bytes written.")
            else:
                print(f"[x] Download incomplete. Expected {file_size} bytes, received {received_bytes} bytes.")
        except Exception as e:
            print(f"[x] Error receiving or writing file: {e}")
