# server/server_main.py
# Starts the multithreaded server application and dispatches client commands.

import os                           # paths for metrics export
import sys                          # process exit handling
import socket                       # TCP server sockets
import threading                    # per-client threads
from cryptography.fernet import InvalidToken      # decrypt error type for PASSWD/ADMIN
from analysis.performance_eval import PerfRecorder, timed   # timing and metrics
from server import file_ops         # file commands and storage helpers
from server import auth             # login, users, and roles

#### Constants ####
BUFFER = 64 * 1024  # 64KB buffer size (reserved for future use)
ENC = "utf-8"       # Encoding format for text commands
BACKLOG = 5         # Max queued connections

# Path to CSV metrics file under the server storage root.
METRICS_FILE = os.path.join(file_ops.STORAGE_ROOT, "server_metrics.csv")

#### Global performance recorder ####
# Shared across all client handler threads.
# Each handler records auth latency, command timings, and session duration.
perf = PerfRecorder()

#### Per-connection session state ####
class ClientSession:
    """
    Holds per-connection state for an authenticated client.

    Tracks:
      - conn / addr: socket and client address
      - username / user_id / role: from auth.user_db
      - storage_root: per-user directory under server/storage/...
      - authenticated: simple flag indicating successful login
    """
    def __init__(self, conn, addr, user_record, storage_root):
        self.conn = conn
        self.addr = addr
        self.username = user_record.get("username")
        self.user_id = user_record.get("user_id")
        self.role = user_record.get("role", auth.ROLE_USER)
        self.storage_root = storage_root
        self.authenticated = True

#### Interactive Setup ####
def _prompt_server_config():
    """
    Prompt the user for server IP and port.

    Returns:
        tuple[str, int] | None:
            (host, port) if valid; None on invalid input.
    """
    print("====== CNT3004 Socket File Sharing Server ======")
    host = input("Enter server IP address (e.g., 0.0.0.0 or localhost): ").strip()
    if not host:
        print("Server IP cannot be empty.")
        return None

    port_str = input("Enter server port: ").strip()
    try:
        port = int(port_str)
    except ValueError:
        print("Port must be an integer.")
        return None

    if not (0 <= port <= 65535):
        print("Port must be between 0-65535.")
        return None

    return host, port

#### Socket helpers ####
def _recv_line(conn, max_bytes=4096):
    """
    Read a single line (terminated by '\n') from a socket.

    This helper is used after authentication for command traffic.
    It protects against partial reads and overly long input.

    Parameters:
        conn (socket.socket): Connected socket.
        max_bytes (int): Hard cap on bytes to read.

    Returns:
        str | None: Line without trailing newline, or None if connection closed.

    Raises:
        ValueError: If input exceeds max_bytes without newline.
    """
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = conn.recv(1024)
        if not chunk:
            if not buf:
                return None
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break

    if not buf:
        return None
    if len(buf) >= max_bytes and b"\n" not in buf:
        raise ValueError("Line too long")

    line, _, _ = buf.partition(b"\n")
    return line.decode(ENC, errors="replace").strip()

def _send_line(conn, text):
    """
    Send a single line to the client, appending '\n'.
    """
    data = (text.rstrip("\n") + "\n").encode(ENC)
    conn.sendall(data)

def _console_shutdown_loop(stop_event):
    """
    Background console loop for server shutdown.

    Typing 'q' and pressing Enter will ask for confirmation and,
    if confirmed, set stop_event so the main listener loop can
    exit cleanly and write metrics.
    """
    while not stop_event.is_set():
        try:
            cmd = input().strip().lower()
        except EOFError:
            # Input stream closed; nothing else we can do.
            return

        if cmd == "q":
            confirm = input("Shut down server and write metrics? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                print("[i] Shutdown requested. Stopping server...")
                stop_event.set()
                return
            else:
                print("[i] Shutdown cancelled. Server is still running.")

#### Command helpers: PASSWD and ADMIN ####
def _handle_self_passwd(session, line):
    """
    Handle PASSWD command for the current user.

    Protocol:
        PASSWD <token>

    Where <token> is an encrypted JSON payload:
        {
            "op": "passwd",
            "old_password": "...",
            "new_password": "..."
        }
    """
    parts = line.split(" ", 1)
    if len(parts) != 2:
        _send_line(session.conn, "ERR PASSWD Usage: PASSWD <token>")
        print(f"[PASSWD] {session.username}: bad syntax")
        return

    token = parts[1].strip()
    try:
        payload = auth.decrypt_payload(token)
    except InvalidToken:
        _send_line(session.conn, "ERR PASSWD Invalid token")
        print(f"[PASSWD] {session.username}: invalid token")
        return
    except ValueError:
        _send_line(session.conn, "ERR PASSWD Invalid payload")
        print(f"[PASSWD] {session.username}: invalid payload")
        return

    if payload.get("op") != "passwd":
        _send_line(session.conn, "ERR PASSWD Invalid op")
        print(f"[PASSWD] {session.username}: invalid op field")
        return

    old_pwd = payload.get("old_password")
    new_pwd = payload.get("new_password")
    if not old_pwd or not new_pwd:
        _send_line(session.conn, "ERR PASSWD Missing fields")
        print(f"[PASSWD] {session.username}: missing fields")
        return

    # Verify current password.
    ok, _ = auth.verify_credentials(session.username, old_pwd)
    if not ok:
        _send_line(session.conn, "ERR PASSWD Invalid old password")
        print(f"[PASSWD] {session.username}: invalid old password")
        return

    # Apply password change with policy enforcement.
    try:
        if not auth.reset_password(session.username, new_pwd):
            _send_line(session.conn, "ERR PASSWD Could not reset password")
            print(f"[PASSWD] {session.username}: reset_password returned False")
            return
    except ValueError as exc:
        msg = str(exc) or "Password policy error"
        _send_line(session.conn, f"ERR PASSWD {msg}")
        print(f"[PASSWD] {session.username}: {msg}")
        return

    _send_line(session.conn, "OK PASSWD Password changed")
    print(f"[PASSWD] {session.username}: password changed")

def _handle_admin_command(session, line):
    """
    Handle ADMIN commands for user management.

    Protocol examples:
        ADMIN ADDUSER <username> <role> <token>
        ADMIN DELUSER <username>
        ADMIN SETROLE <username> <role>
        ADMIN RESETPASS <username> <token>
        ADMIN LISTUSERS

    Only sessions with role 'admin' may use these commands.
    """
    if session.role != auth.ROLE_ADMIN:
        _send_line(session.conn, "ERR ADMIN Not authorized")
        print(f"[ADMIN] denied for non-admin user '{session.username}'")
        return

    parts = line.split()
    if len(parts) < 2:
        _send_line(session.conn, "ERR ADMIN Missing subcommand")
        print(f"[ADMIN] {session.username}: missing subcommand")
        return

    sub = parts[1].upper()

    # ADMIN ADDUSER <username> <role> <token>
    if sub == "ADDUSER":
        if len(parts) < 5:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN ADDUSER <username> <role> <token>")
            print(f"[ADMIN ADDUSER] {session.username}: bad syntax")
            return

        username = parts[2]
        role = parts[3]
        token = parts[4]

        try:
            payload = auth.decrypt_payload(token)
        except InvalidToken:
            _send_line(session.conn, "ERR ADMIN Invalid token")
            print(f"[ADMIN ADDUSER] {session.username}: invalid token")
            return
        except ValueError:
            _send_line(session.conn, "ERR ADMIN Invalid payload")
            print(f"[ADMIN ADDUSER] {session.username}: invalid payload")
            return

        if payload.get("op") != "adduser":
            _send_line(session.conn, "ERR ADMIN Invalid op")
            print(f"[ADMIN ADDUSER] {session.username}: invalid op field")
            return

        password = payload.get("password")
        if not password:
            _send_line(session.conn, "ERR ADMIN Missing password")
            print(f"[ADMIN ADDUSER] {session.username}: missing password")
            return

        try:
            record = auth.register_user(username, password, role=role)
        except ValueError as exc:
            _send_line(session.conn, f"ERR ADMIN {exc}")
            print(f"[ADMIN ADDUSER] {session.username}: {exc}")
            return

        # Create per-user storage directory for the new user.
        file_ops.init_user_storage_dir(record["user_id"], record["username"])

        _send_line(session.conn, f"OK ADMIN ADDUSER {username}")
        print(f"[ADMIN ADDUSER] {session.username}: added user '{username}' with role '{role}'")

    # ADMIN DELUSER <username>
    elif sub == "DELUSER":
        if len(parts) != 3:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN DELUSER <username>")
            print(f"[ADMIN DELUSER] {session.username}: bad syntax")
            return

        username = parts[2]
        if not auth.delete_user(username):
            _send_line(session.conn, "ERR ADMIN User not found")
            print(f"[ADMIN DELUSER] {session.username}: user '{username}' not found")
            return

        _send_line(session.conn, f"OK ADMIN DELUSER {username}")
        print(f"[ADMIN DELUSER] {session.username}: deleted user '{username}'")

    # ADMIN SETROLE <username> <role>
    elif sub == "SETROLE":
        if len(parts) != 4:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN SETROLE <username> <role>")
            print(f"[ADMIN SETROLE] {session.username}: bad syntax")
            return

        username = parts[2]
        role = parts[3]

        try:
            if not auth.set_role(username, role):
                _send_line(session.conn, "ERR ADMIN User not found")
                print(f"[ADMIN SETROLE] {session.username}: user '{username}' not found")
                return
        except ValueError as exc:
            _send_line(session.conn, f"ERR ADMIN {exc}")
            print(f"[ADMIN SETROLE] {session.username}: {exc}")
            return

        _send_line(session.conn, f"OK ADMIN SETROLE {username} {role}")
        print(f"[ADMIN SETROLE] {session.username}: set role for '{username}' to '{role}'")

    # ADMIN RESETPASS <username> <token>
    elif sub == "RESETPASS":
        if len(parts) < 4:
            _send_line(session.conn, "ERR ADMIN Usage: ADMIN RESETPASS <username> <token>")
            print(f"[ADMIN RESETPASS] {session.username}: bad syntax")
            return

        username = parts[2]
        token = parts[3]

        try:
            payload = auth.decrypt_payload(token)
        except InvalidToken:
            _send_line(session.conn, "ERR ADMIN Invalid token")
            print(f"[ADMIN RESETPASS] {session.username}: invalid token")
            return
        except ValueError:
            _send_line(session.conn, "ERR ADMIN Invalid payload")
            print(f"[ADMIN RESETPASS] {session.username}: invalid payload")
            return

        if payload.get("op") != "resetpass":
            _send_line(session.conn, "ERR ADMIN Invalid op")
            print(f"[ADMIN RESETPASS] {session.username}: invalid op field")
            return

        new_pwd = payload.get("new_password")
        if not new_pwd:
            _send_line(session.conn, "ERR ADMIN Missing new password")
            print(f"[ADMIN RESETPASS] {session.username}: missing new password")
            return

        try:
            ok = auth.reset_password(username, new_pwd)
        except ValueError as exc:
            msg = str(exc) or "Password policy error"
            _send_line(session.conn, f"ERR ADMIN {msg}")
            print(f"[ADMIN RESETPASS] {session.username}: {msg}")
            return

        if not ok:
            _send_line(session.conn, "ERR ADMIN User not found")
            print(f"[ADMIN RESETPASS] {session.username}: user '{username}' not found")
            return

        _send_line(session.conn, f"OK ADMIN RESETPASS {username}")
        print(f"[ADMIN RESETPASS] {session.username}: reset password for '{username}'")

    # ADMIN LISTUSERS
    elif sub == "LISTUSERS":
        users = auth.list_users()
        _send_line(session.conn, "OK ADMIN LISTUSERS BEGIN")
        for rec in users:
            line = f"{rec.get('username')} {rec.get('role')} {rec.get('user_id')}"
            _send_line(session.conn, line)
        _send_line(session.conn, "OK ADMIN LISTUSERS END")
        print(f"[ADMIN LISTUSERS] {session.username}: listed users")

    else:
        _send_line(session.conn, "ERR ADMIN Unknown subcommand")
        print(f"[ADMIN] {session.username}: unknown subcommand '{sub}'")

#### Client handler ####
def handle_client(conn, addr):
    """
    Handle communication with a single connected client.

    Steps:
      1. Run encrypted authentication via auth.handle_auth().
      2. On success, build a ClientSession with per-user storage_root.
      3. Enter a loop to accept commands (UPLOAD, DOWNLOAD, DELETE, DIR,
         SUBFOLDER, PASSWD, ADMIN, LOGOUT).
      4. Record timing metrics for auth and overall session.
    """
    print(f"[+] New connection from {addr}")
    session_timer = timed()   # measure total session duration
    session = None            # filled in after successful auth

    try:
        #### 1. Authentication handshake ####
        auth_timer = timed()
        ok, user_record = auth.handle_auth(conn, addr)
        auth_latency = auth_timer()
        perf.record_response(operation="auth", seconds=auth_latency, source="server")

        if not ok or user_record is None:
            print(f"[auth] Login failed for {addr}")
            return

        role = user_record.get("role", auth.ROLE_USER)
        user_id = user_record.get("user_id", "")
        username = user_record.get("username", "")

        #### 2. Prepare user-specific storage directory ####
        storage_root = file_ops.init_user_storage_dir(user_id, username)
        session = ClientSession(conn, addr, user_record, storage_root)

        print(
            f"[auth] Authenticated user='{username}' role='{role}' "
            f"id='{user_id}' from {addr}"
        )
        print(f"[auth] Storage root for this user: {storage_root}")

        #### 3. Main command loop ####
        while True:
            line = _recv_line(conn)
            if line is None:
                # Client closed the connection cleanly.
                print(f"[session] Client {addr} closed the connection.")
                break

            if not line:
                # Ignore empty lines.
                continue

            cmd = line.split()[0].upper()

            if cmd == "LOGOUT":
                _send_line(conn, "OK LOGOUT Goodbye")
                print(f"[session] {username} requested logout.")
                break

            elif cmd == "UPLOAD":
                file_ops.handle_upload(session, line, perf)

            elif cmd == "DOWNLOAD":
                file_ops.handle_download(session, line, perf)

            elif cmd == "DELETE":
                file_ops.handle_delete(session, line, perf)

            elif cmd == "DIR":
                file_ops.handle_dir(session, line, perf)

            elif cmd == "SUBFOLDER":
                file_ops.handle_subfolder(session, line, perf)

            elif cmd == "PASSWD":
                _handle_self_passwd(session, line)

            elif cmd == "ADMIN":
                _handle_admin_command(session, line)

            else:
                _send_line(conn, "ERR UNKNOWN Command")
                print(f"[session] {username}: unknown command '{line}'")

    except ConnectionResetError:
        # Typical when client crashes or closes the socket abruptly.
        print(f"[x] Connection reset by {addr}")

    except Exception as exc:
        # Generic safety net around the per-client thread.
        print(f"[x] Error with {addr}: {exc}")

    finally:
        #### 4. Cleanup and session timing ####
        try:
            conn.close()
        except Exception:
            pass

        elapsed = session_timer()
        perf.record_response(operation="session", seconds=elapsed, source="server")
        print(f"[-] Disconnected from {addr} (Session duration: {elapsed:.2f}s)")

#### Main entry point ####
def main():
    """
    Main entry point for the server.

    Responsibilities:
      - Initialize auth store (user DB + secret key).
      - Init base storage paths.
      - Prompt for bind address and port.
      - Accept clients on a listening socket and spawn a thread per client.
      - Record total server uptime for performance analysis.
      - Support graceful shutdown via 'q' + Enter from the console.
    """
    # Initialize authentication storage (user DB and secret key) before serving.
    auth.init_auth_store()

    # Init the global storage root.
    # Per-user folders are created lazily by init_user_storage_dir().
    file_ops.init_storage_root()

    config = _prompt_server_config()
    if not config:
        print("[x] Invalid server configuration. Returning to main menu.\n")
        return False

    host, port = config
    print(f"[i] Starting server on {host}:{port} ...")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((host, port))
        server_sock.listen(BACKLOG)
        server_sock.settimeout(1.0)  # Allows periodic shutdown checks
    except OSError as exc:
        print(f"[x] Failed to start server: {exc}")
        return False

    print(
        f"[✓] Server listening on {host}:{port}\n"
        "Type 'q' and press Enter to stop the server.\n"
    )

    start_timer = timed()  # track server uptime

    # Event used to coordinate shutdown between console thread and accept loop.
    shutdown_event = threading.Event()

    # Start background console thread to watch for 'q'.
    console_thread = threading.Thread(
        target=_console_shutdown_loop,
        args=(shutdown_event,),
        daemon=True,
    )
    console_thread.start()

    try:
        while not shutdown_event.is_set():
            try:
                conn, addr = server_sock.accept()
            except socket.timeout:
                # Timeout so we can re-check shutdown_event regularly.
                continue
            except OSError:
                # Listening socket was closed; exit loop.
                break

            # Spawn a new daemon thread for each client connection.
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        # Emergency Ctrl+C. Try to shut down cleanly anyway.
        print("\n[i] Server interrupted via Ctrl+C. Stopping...")
        shutdown_event.set()

    finally:
        # Stop accepting new connections and unblock accept().
        try:
            server_sock.close()
        except Exception:
            pass

        # Ensure the console thread (if still running) knows we're done.
        shutdown_event.set()

        uptime = start_timer()
        perf.record_response(operation="server_uptime", seconds=uptime, source="server")
        print(f"[i] Server stopped. Total runtime: {uptime:.2f}s")

        # Export metrics for offline analysis.
        try:
            # storage root already exists from file_ops.init_storage_root()
            perf.to_csv(METRICS_FILE)
            print(f"[i] Wrote performance metrics to {METRICS_FILE}\n")
        except Exception as exc:
            print(f"[x] Failed to write performance metrics: {exc}\n")

    # Return False so main.py menu reloads.
    return False

#### Run as script ####
if __name__ == "__main__":
    main()
