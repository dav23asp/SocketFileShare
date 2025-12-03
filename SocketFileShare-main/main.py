# main.py
# Entry launcher for CNT3004 Socket File Sharing System.
# Allows the user to start the server, start the client, or quit.

import sys          # process exit handling
import os           # filesystem checks and paths
import shutil       # wiping storage
import getpass      # hidden password input
from server import auth, file_ops       # auth bootstrap and storage setup

#### Menu Display ####
MENU = (
    "\n"
    "=== CNT3004 Socket-Based File Sharing System ===\n"
    "Select mode to run:\n"
    "  1. Server\n"
    "  2. Client\n"
    "  3. Quit\n"
    "================================================\n"
)

#### Server data helpers ####
def _server_data_paths():
    """
    Return the paths used for server-side persistent data.

    This includes:
      - The JSON user database.
      - The symmetric encryption key for auth.
      - The root directory for all server-side storage.
    """
    user_db = auth.USER_DB
    secret_key = auth.SECRET_KEY_FILE
    storage_root = file_ops.STORAGE_ROOT
    return user_db, secret_key, storage_root

def _server_data_exists():
    """
    Determine whether any server-side data already exists on disk.

    Returns:
        bool: True if at least one of the user DB, key file, or storage
              directory exists; False for a completely fresh setup.
    """
    user_db, secret_key, storage_root = _server_data_paths()
    paths = [user_db, secret_key, storage_root]
    return any(os.path.exists(p) for p in paths)

def _reset_server_data():
    """
    Remove existing server-side data for a clean reinitialization.

    This deletes:
      - The user database JSON file (if present).
      - The auth secret key file (if present).
      - The entire server storage tree (including per-user folders
        and the embedded database directory).
    """
    user_db, secret_key, storage_root = _server_data_paths()

    # Remove standalone files (user DB and secret key).
    for path in (user_db, secret_key):
        if os.path.exists(path):
            try:
                os.remove(path)
                print(f"[INFO] Removed file: {path}")
            except OSError as exc:
                print(f"[WARN] Could not remove file {path}: {exc}")

    # Remove the storage root (which also contains the database directory).
    if os.path.exists(storage_root):
        try:
            shutil.rmtree(storage_root)
            print(f"[INFO] Removed folder: {storage_root}")
        except OSError as exc:
            print(f"[WARN] Could not remove folder {storage_root}: {exc}")

def _prompt_yes_no(prompt, default=False):
    """
    Ask the user a yes/no question and return their answer.

    Parameters:
        prompt (str): Text to display (e.g., "Reset data? [y/N]: ").
        default (bool): Value to return if the user presses Enter.

    Returns:
        bool: True for "yes", False for "no".
    """
    while True:
        raw = input(prompt).strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Please enter 'y' or 'n'.")

def _create_initial_admin():
    """
    Interactively create the first admin account on the server.

    This function:
      - Prompts for a new admin username and password.
      - Registers the admin via auth.register_user().
      - Initializes a per-user storage directory under server/storage.
    """
    print("\n[SETUP] Create initial admin account.")
    while True:
        username = input("Admin username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue

        pwd1 = getpass.getpass("Admin password: ")
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match. Try again.\n")
            continue

        try:
            record = auth.register_user(
                username,
                pwd1,
                role=auth.ROLE_ADMIN,
                overwrite=False,
            )
        except ValueError as exc:
            # For example: username already exists or password too short.
            print(f"Could not create admin: {exc}")
            continue

        # Prepare a per-admin storage directory under:
        #   server/storage/ID_<user_id>_<username>/
        file_ops.init_user_storage_dir(record["user_id"], record["username"])
        print(f"[INFO] Admin user '{username}' created with id '{record['user_id']}'.\n")
        break

def _bootstrap_server():
    """
    Prepare authentication and storage data before running the server.

    Steps:
      - Detect whether server data already exists (user DB, key, or storage).
      - Optionally reset all data if the user requests a clean start.
      - Make sure there is at least one admin account configured.
    """
    has_data = _server_data_exists()

    if not has_data:
        # Completely fresh setup: create the first admin account.
        print("\n[SETUP] No existing server data found.")
        _create_initial_admin()
        return True

    print("\n[SETUP] Existing server data detected (users, keys, or storage).")
    reset = _prompt_yes_no(
        "Reset server data to default and create a new admin? [y/N]: ",
        default=False,
    )

    if reset:
        print("[INFO] Resetting server data...")
        _reset_server_data()
        _create_initial_admin()
        return True

    # Keep existing data, but verify that at least one admin user exists.
    users = auth.list_users()
    admins = [u for u in users if u.get("role") == auth.ROLE_ADMIN]

    if not admins:
        print("\n[SETUP] No admin users found in existing data.")
        _create_initial_admin()

    print("[INFO] Using existing server data.\n")
    return True

#### Main Launcher ####
def main():
    """
    Main entry point for the launcher menu.

    This function:
      - Presents a text menu (Server / Client / Quit).
      - Bootstraps server-side data before starting the server.
      - Starts either the server program or the client program.
      - Handles Ctrl+C / EOF robustly so the menu can recover or exit cleanly.
    """
    in_subprogram = False  # Track whether we're inside server/client mode

    try:
        while True:
            try:
                # Show the main menu and read the user's choice.
                print(MENU, end="")     # Prevent extra newlines
                choice = input("\nEnter choice (1-3): ").strip()

                #### Server Option ####
                if choice == "1":
                    # Prepare server data (admin user, storage directories).
                    if not _bootstrap_server():
                        continue

                    from server.server_main import main as server_main
                    print("\n[INFO] Starting server...\n\n")
                    in_subprogram = True
                    success = server_main()
                    in_subprogram = False
                    if not success:
                        # Server requested a return to the launcher.
                        continue

                #### Client Option ####
                elif choice == "2":
                    from client.client_main import main as client_main
                    print("\n[INFO] Starting client...\n\n")
                    in_subprogram = True
                    success = client_main()
                    in_subprogram = False
                    if not success:
                        # Client requested a return to the launcher.
                        continue

                #### Quit Option ####
                elif choice == "3":
                    print("Exiting program.")
                    break

                #### Invalid Option ####
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.\n")

            #### Inner Ctrl+C or EOF Handling ####
            except (KeyboardInterrupt, EOFError):
                if in_subprogram:
                    # If a subprogram was running, return to the main menu.
                    print("\n[i] Interrupted. Returning to main menu.\n")
                    in_subprogram = False
                    continue
                else:
                    # If already at the top level, exit the process.
                    print("\n[i] Keyboard interrupt detected. Exiting program.\n")
                    sys.exit(0)

    #### Outer Ctrl+C or EOF Handling ####
    except (KeyboardInterrupt, EOFError):
        # Catch any outer-level signals and exit cleanly.
        print("\n[i] Launcher interrupted. Exiting program.\n")
        sys.exit(0)

#### Run as Script ####
if __name__ == "__main__":
    main()
