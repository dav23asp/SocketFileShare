# client/client_main.py
# Runs the client connection and interactive command session.

import socket       # client TCP connect / error types
import sys          # launcher exit codes
import getpass      # hidden password prompts
from client.commands import ClientSession             # high-level client session API
from analysis.performance_eval import PerfRecorder, timed   # client-side session metrics

#### Constants ####
USAGE = (
    "Commands:\n"
    "  passwd                            Change your password\n"
    "  upload <local_path> [remote]      Upload a file\n"
    "  download <remote> [local]         Download a file\n"
    "  delete <remote_path>              Delete a file\n"
    "  dir [subpath]                     List directory\n"
    "  subfolder <create|delete> <path>  Manage subfolders\n"
    "  admin-adduser <user> <role>       Add a user (admin)\n"
    "  admin-deluser <user>              Delete a user (admin)\n"
    "  admin-setrole <user> <role>       Change a user's role (admin)\n"
    "  admin-resetpass <user>            Reset a user's password (admin)\n"
    "  admin-listusers                   List users (admin)\n"
    "  logout                            Logout and re-login\n"
    "  help                              Show this help\n"
    "  quit / exit                       Logout and exit\n"
)

#### Interactive Setup ####
def _prompt_server_target():
    """
    Prompt for server IP and port and return them as (ip, port).

    Exits the program if the input is invalid or out of range.
    """
    print("====== CNT3004 Socket File Sharing Client ======")

    # Ask for server IP / hostname.
    server_ip = input("Enter server IP address: ").strip()
    if not server_ip:
        print("Server IP cannot be empty.")
        sys.exit(1)

    # Ask for TCP port and validate it is an integer in 0-65535.
    port_str = input("Enter server port: ").strip()
    try:
        server_port = int(port_str)
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)

    if not (0 <= server_port <= 65535):
        print("Port must be between 0-65535.")
        sys.exit(1)

    return server_ip, server_port


def _initial_auth(session):
    """
    Run the initial login sequence after the TCP connection is established.

    Prompts for username and password, calls session.auth(), and repeats
    until authentication succeeds or the user cancels.

    Returns:
        bool: True if authentication succeeded, False otherwise.
    """
    while True:
        # If TCP is not connected, try to connect first.
        if not session.connected:
            print("[i] Connecting to server...")
            session.connect()
            if not session.connected:
                # Connection failed; let caller decide what to do.
                print("[x] Could not connect to server.")
                return False

        print("---- Login ----")

        # Ask for username and make sure it is not empty.
        username = input("user: ").strip()
        if not username:
            print("[x] Username cannot be empty.")
            continue

        # Password is taken via `getpass` so it is not echoed.
        password = getpass.getpass("pass: ")

        # Delegate the actual authentication protocol to ClientSession.auth().
        ok = session.auth(username, password)
        if ok:
            # The server has verified the credentials and
            # the session has username / user_id / role filled in.
            return True

        # If not ok, ask if user wants to try again.
        choice = input("Authentication failed. Try again? [y/N]: ").strip().lower()
        if choice not in ("y", "yes"):
            return False

#### Command handlers ####
def _handle_passwd(session):
    """
    Process the 'passwd' command to change the current user's password.
    """
    if not session.authenticated:
        print("[!] You must authenticate first.")
        return

    old_pwd = getpass.getpass("Old password: ")
    new_pwd = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")

    if new_pwd != confirm:
        print("[x] New passwords do not match.")
        return

    session.change_password(old_pwd, new_pwd)

def _handle_admin_adduser(session, parts):
    """
    Process the 'admin-adduser' command to create a new user account.
    """
    if len(parts) != 3:
        print("Use: admin-adduser <username> <role>")
        return

    username = parts[1]
    role = parts[2]

    pwd = getpass.getpass(f"New password for '{username}': ")
    confirm = getpass.getpass("Confirm password: ")
    if pwd != confirm:
        print("[x] Passwords do not match.")
        return

    session.admin_adduser(username, role, pwd)

def _handle_admin_deluser(session, parts):
    """
    Process the 'admin-deluser' command to remove an existing user.
    """
    if len(parts) != 2:
        print("Use: admin-deluser <username>")
        return

    session.admin_deluser(parts[1])

def _handle_admin_setrole(session, parts):
    """
    Process the 'admin-setrole' command to change a user's role.
    """
    if len(parts) != 3:
        print("Use: admin-setrole <username> <role>")
        return

    session.admin_setrole(parts[1], parts[2])

def _handle_admin_resetpass(session, parts):
    """
    Process the 'admin-resetpass' command to reset another user's password.
    """
    if len(parts) != 2:
        print("Use: admin-resetpass <username>")
        return

    username = parts[1]
    new_pwd = getpass.getpass(f"New password for '{username}': ")
    confirm = getpass.getpass("Confirm password: ")
    if new_pwd != confirm:
        print("[x] Passwords do not match.")
        return

    session.admin_resetpass(username, new_pwd)

def _handle_logout(session):
    """
    Process the 'logout' command and optionally start a new login session.

    Returns:
        bool: True to keep the client running, False to exit.
    """
    session.logout()
    print("")

    if _initial_auth(session):
        print("Re-authenticated. Type 'help' for commands. Type 'quit' to exit.\n")
        return True

    print("[i] Logout complete. No new authentication requested.")
    return False

def _dispatch(session, line):
    """
    Parse a user input line and dispatch it to the appropriate handler.

    Returns:
        bool: False to terminate the main loop; True to continue.
    """
    if not line:
        # Empty input line; keep loop going.
        return True

    parts = line.split()
    cmd = parts[0].lower()

    # Quit / exit: logout and exit client entirely.
    if cmd in ("quit", "exit"):
        session.logout()
        return False

    # Logout: close current session, then run a new login sequence.
    if cmd == "logout":
        return _handle_logout(session)

    # Help text request.
    if cmd == "help":
        print(USAGE)
        return True

    # Change password.
    if cmd == "passwd":
        _handle_passwd(session)
        return True

    # Upload file.
    if cmd == "upload":
        if len(parts) >= 2:
            local_path = parts[1]
            remote_name = parts[2] if len(parts) >= 3 else None
            session.upload(local_path, remote_name)
        else:
            print("Use: upload <local_path> [remote]")
        return True

    # Download file.
    if cmd == "download":
        if len(parts) >= 2:
            remote_name = parts[1]
            local_path = parts[2] if len(parts) >= 3 else None
            session.download(remote_name, local_path)
        else:
            print("Use: download <remote> [local]")
        return True

    # Delete file.
    if cmd == "delete":
        if len(parts) == 2:
            session.delete(parts[1])
        else:
            print("Use: delete <remote_path>")
        return True

    # Directory listing.
    if cmd == "dir":
        subpath = parts[1] if len(parts) >= 2 else None
        session.dir_list(subpath)
        return True

    # Subfolder create/delete.
    if cmd == "subfolder":
        if len(parts) >= 3:
            action = parts[1].lower()
            path = " ".join(parts[2:])
            session.subfolder(action, path)
        else:
            print("Use: subfolder <create|delete> <path>")
        return True

    # Admin commands: forwarded to corresponding ClientSession admin helpers.
    if cmd == "admin-adduser":
        _handle_admin_adduser(session, parts)
        return True

    if cmd == "admin-deluser":
        _handle_admin_deluser(session, parts)
        return True

    if cmd == "admin-setrole":
        _handle_admin_setrole(session, parts)
        return True

    if cmd == "admin-resetpass":
        _handle_admin_resetpass(session, parts)
        return True

    if cmd == "admin-listusers":
        session.admin_listusers()
        return True

    # Fallback for unknown commands.
    print("Unknown or malformed command. Type 'help'.")
    return True


#### Main Entry Point ####
def main():
    """
    Launch the client program and drive the interactive command session.

    Returns:
        bool: True on normal exit, False when setup or auth fails.
    """
    server_ip, server_port = _prompt_server_target()

    # Local performance recorder for the *client-side* session lifetime.
    # Per-command metrics (auth, upload, download, etc.) are recorded inside the ClientSession instance (client.commands).
    # This recorder focuses on the overall interactive session length from the user's perspective.
    perf = PerfRecorder()

    # Initialize client session and timer for high-level session duration.
    session = ClientSession(server_ip, server_port)
    timer = timed()  # Tracks entire time spent in this client run.

    # Open TCP connection once; _initial_auth may reconnect if needed.
    session.connect()
    if not session.connected:
        print("[x] Could not establish connection. Returning to main menu.\n")
        return False

    # Perform initial authentication (server-side auth is authoritative).
    if not _initial_auth(session):
        session.close()
        print("[x] Authentication failed. Returning to main menu.\n")
        elapsed = timer()
        perf.record_response(operation="client_session", seconds=elapsed, source="client")
        return False

    print("Connected and authenticated. Type 'help' for commands.\n")

    # Interactive command loop.
    try:
        while True:
            try:
                # Prompt shows current username and role returned by the server.
                prompt_user = session.username or "guest"
                prompt_role = session.role or "none"
                line = input(f"[{prompt_user}@{prompt_role}]> ").strip()
            except EOFError:
                # Ctrl+D / end-of-file: treat as quit.
                line = "quit"
            except KeyboardInterrupt:
                # Ctrl+C from the user: also treat as quit.
                print("\n[i] Interrupted.")
                line = "quit"

            try:
                keep_running = _dispatch(session, line)
            except (socket.error, OSError) as e:
                # Network failure ends the loop; higher-level retry could be added.
                print(f"Network error: {e}")
                keep_running = False

            if not keep_running:
                break

    finally:
        # Record total client session duration for performance evaluation.
        elapsed = timer()
        perf.record_response(operation="client_session", seconds=elapsed, source="client")
        session.close()
        print(f"Disconnected from server. Session duration: {elapsed:.2f}s\n")

    # Indicate normal exit to main.py launcher.
    return True

#### Run as Script ####
if __name__ == "__main__":
    main()
