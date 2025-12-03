# server/file_ops.py
# Handles file operations for upload, download, delete, directory listing, and subfolder management.

import os       # storage paths and filesystem work
import threading
from analysis.performance_eval import timed  # timing for file operations

#### Paths and constants ####
ENC = "utf-8"
BASE_DIR = os.path.dirname(__file__)

# Root directory for all file data managed by the server.
# This is treated as the "root" of the folder system.
STORAGE_ROOT = os.path.join(BASE_DIR, "storage")

# Suggested chunk size for streaming large files (upload/download).
CHUNK_SIZE = 64 * 1024  # 64 KB

# Track files currently being processed (uploads/downloads/deletes).
_BUSY_LOCK = threading.Lock()
_BUSY_PATHS = set()


def _mark_busy(path):
    """
    Mark a path as busy.

    Returns:
        bool: True if the path was free and is now marked busy.
              False if it was already busy.
    """
    abs_path = os.path.abspath(path)
    with _BUSY_LOCK:
        if abs_path in _BUSY_PATHS:
            return False
        _BUSY_PATHS.add(abs_path)
        return True


def _clear_busy(path):
    """Remove a path from the busy set."""
    abs_path = os.path.abspath(path)
    with _BUSY_LOCK:
        _BUSY_PATHS.discard(abs_path)


def _recv_line(conn, max_bytes=4096):
    """
    Read a single line (terminated by '\n') from a socket.

    Returns:
        str or None: Line without trailing newline, or None if connection closed.
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

#### Path helpers ####
def _make_dirs(path):
    """
    Create a directory tree if it does not exist.

    This is used both for the global storage root and for per-user folders.
    """
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def init_storage_root():
    """
    Make sure the global storage root exists.

    main.py or server_main.py should call this during server bootstrap.
    """
    _make_dirs(STORAGE_ROOT)


def get_user_storage_dir(user_id, username):
    """
    Compute the absolute path for a user's storage directory.

    Layout:
        server/storage/ID_<user_id>_<username>/

    Parameters:
        user_id  (str): Numeric ID from auth (e.g., "0001", "0002").
        username (str): Associated username (e.g., "helloworld").

    Returns:
        str: Absolute path to that user's storage directory (not created).
    """
    init_storage_root()

    # Fallbacks in case something is missing; helps avoid crashing.
    if not user_id:
        user_id = "UNKNOWN"
    if not username:
        username = "unknown"

    folder_name = f"ID_{user_id}_{username}"
    # NOTE: If usernames may contain path-unsafe chars, a sanitization step can be added here.
    return os.path.abspath(os.path.join(STORAGE_ROOT, folder_name))


def init_user_storage_dir(user_id, username):
    """
    Make sure a user's storage directory exists and return its path.

    Parameters:
        user_id  (str): Numeric ID from auth (e.g., "0001").
        username (str): Associated username.

    Returns:
        str: Absolute path to the existing per-user storage directory.
    """
    user_dir = get_user_storage_dir(user_id, username)
    _make_dirs(user_dir)
    return user_dir


def resolve_path(session, rel_path):
    """
    Map a client-provided relative path to an absolute path inside
    the session's storage_root. Reject attempts to leave that root.

    Parameters:
        session: Object with a 'storage_root' attribute (e.g., ClientSession).
        rel_path (str): Relative path sent by the client (e.g., "file.txt", "subdir/file.bin").

    Returns:
        str: Absolute path under session.storage_root.

    Raises:
        ValueError: If the resolved path is outside the storage root, or invalid.
    """
    # Initialize storage_root as absolute to avoid surprises.
    base = os.path.abspath(session.storage_root)
    target = os.path.abspath(os.path.join(base, rel_path))

    try:
        common = os.path.commonpath([base, target])
    except ValueError:
        # Occurs if paths are on different drives or malformed
        raise ValueError("Invalid path")

    if common != base:
        # Prevent directory traversal outside the user's folder
        raise ValueError("Path outside storage root")

    return target


def _send_line(conn, text):
    """
    Send a single line to the client, appending '\n'.

    Parameters:
        conn: Socket-like object (has sendall()).
        text (str): Response line to send.
    """
    data = (text.rstrip("\n") + "\n").encode(ENC)
    conn.sendall(data)

#### Command handlers ####
def handle_upload(session, line, perf):
    """
    Handle file upload request from a client.

    Protocol:
        UPLOAD <remote_path> <size_bytes>

    Where:
        remote_path: Path relative to the user's storage root.
        size_bytes:  Decimal size of the file in bytes.

    Overwrite handling:
        - If file exists:
            server:  "EXISTS UPLOAD <remote_path>"
            client:  "OVERWRITE" or "SKIP"

        - If "SKIP":
            server:  "OK UPLOAD SKIPPED <remote_path>"
    """
    timer = timed()  # measure upload handling time
    received_bytes = 0
    target_path = None

    try:
        # Only authenticated clients can upload files.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR UPLOAD Not authenticated")
            print("[UPLOAD] denied: client not authenticated")
            return

        parts = line.split()
        if len(parts) < 3:
            _send_line(session.conn, "ERR UPLOAD Usage: UPLOAD <remote_path> <size_bytes>")
            print("[UPLOAD] failed: bad syntax")
            return

        # Expected format: UPLOAD <remote_path> <size_bytes>
        _, rel_path, size_str = parts[0], parts[1], parts[2]

        # Validate and parse the size field.
        try:
            file_size = int(size_str)
            if file_size < 0:
                raise ValueError
        except ValueError:
            _send_line(session.conn, "ERR UPLOAD Invalid size")
            print("[UPLOAD] failed: invalid size")
            return

        # Translate client path to a safe absolute path inside the user's folder.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR UPLOAD Invalid path")
            print(f"[UPLOAD] failed: invalid path '{rel_path}'")
            return

        # Reserve this path so no other operation touches it at the same time.
        if not _mark_busy(target_path):
            _send_line(session.conn, "ERR UPLOAD File is in use")
            print(f"[UPLOAD] failed: file in use '{target_path}'")
            return

        # Create parent directories if needed.
        parent_dir = os.path.dirname(target_path)
        _make_dirs(parent_dir)

        # If the path points to a directory, reject.
        if os.path.isdir(target_path):
            _send_line(session.conn, "ERR UPLOAD Target is a directory")
            print(f"[UPLOAD] failed: target is directory '{target_path}'")
            return

        # Overwrite prompt if file already exists.
        if os.path.exists(target_path):
            _send_line(session.conn, f"EXISTS UPLOAD {rel_path}")
            resp = _recv_line(session.conn)
            if resp is None:
                print("[UPLOAD] client disconnected during overwrite prompt")
                return

            resp = resp.strip().upper()
            if resp == "SKIP":
                _send_line(session.conn, f"OK UPLOAD SKIPPED {rel_path}")
                print(f"[UPLOAD] client skipped overwrite for '{target_path}'")
                return
            if resp != "OVERWRITE":
                _send_line(session.conn, "ERR UPLOAD Invalid overwrite response")
                print(f"[UPLOAD] failed: unexpected overwrite reply '{resp}'")
                return

        print(f"[UPLOAD] Starting: {rel_path} ({file_size} bytes) -> {target_path}")

        # Send READY so client can start streaming bytes.
        _send_line(session.conn, "READY")

        try:
            with open(target_path, "wb") as f:
                # Receive exactly file_size bytes from the client.
                while received_bytes < file_size:
                    remaining = file_size - received_bytes
                    to_read = min(CHUNK_SIZE, remaining)
                    chunk = session.conn.recv(to_read)
                    if not chunk:
                        raise ConnectionResetError("Connection lost during transfer")
                    f.write(chunk)
                    received_bytes += len(chunk)

            _send_line(session.conn, f"OK UPLOAD {rel_path}")
            print(f"[UPLOAD] Finished. {rel_path} uploaded by {session.username}")
        except OSError as e:
            print(f"[UPLOAD] File IO error: {e}")
            _send_line(session.conn, f"ERR UPLOAD Server disk error: {e}")
        except Exception as e:
            print(f"[UPLOAD] Transfer error: {e}")
            _send_line(session.conn, "ERR UPLOAD Transfer interrupted")

    except Exception as e:
        print(f"[UPLOAD] Critical error: {e}")
        try:
            _send_line(session.conn, "ERR UPLOAD Internal error")
        except Exception:
            pass

    finally:
        if target_path is not None:
            _clear_busy(target_path)
        elapsed = timer()
        perf.record_transfer(operation="upload", bytes_count=received_bytes, seconds=elapsed, source="server")


def handle_download(session, line, perf):
    """
    Handle file download request from a client.

    Protocol:
        DOWNLOAD <remote_path>

    Where:
        remote_path: Path relative to the user's storage root.

    Steps:
        - Server sends:  "SIZE <file_size>"
        - Client sends:  "READY"
        - Server streams raw bytes.
    """
    timer = timed()  # measure download handling time
    sent_bytes = 0
    target_path = None

    try:
        # Only authenticated clients can download files.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR DOWNLOAD Not authenticated")
            print("[DOWNLOAD] denied: client not authenticated")
            return

        parts = line.split()
        if len(parts) != 2:
            _send_line(session.conn, "ERR DOWNLOAD Usage: DOWNLOAD <remote_path>")
            print("[DOWNLOAD] failed: bad syntax")
            return

        _, rel_path = parts[0], parts[1]

        # Map the remote path to the actual file in the user's storage directory.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR DOWNLOAD Invalid path")
            print(f"[DOWNLOAD] failed: invalid path '{rel_path}'")
            return

        # Reserve file for this transfer.
        if not _mark_busy(target_path):
            _send_line(session.conn, "ERR DOWNLOAD File is in use")
            print(f"[DOWNLOAD] failed: file in use '{target_path}'")
            return

        if not os.path.exists(target_path):
            _send_line(session.conn, "ERR DOWNLOAD File not found")
            print(f"[DOWNLOAD] failed: file not found at {target_path}")
            return

        if not os.path.isfile(target_path):
            _send_line(session.conn, "ERR DOWNLOAD Target is not a file")
            print(f"[DOWNLOAD] failed: target is not a file '{target_path}'")
            return

        file_size = os.path.getsize(target_path)

        print(f"[DOWNLOAD] Preparing to send: {rel_path} ({file_size} bytes)...")

        # Send size header: "SIZE <file_size>"
        _send_line(session.conn, f"SIZE {file_size}")

        # Wait for client READY
        try:
            resp = _recv_line(session.conn)
            if resp != "READY":
                print(f"[DOWNLOAD] Client rejected transfer or sent unexpected response: {resp}")
                return
        except Exception as e:
            print(f"[DOWNLOAD] Client READY failed: {e}")
            return

        try:
            with open(target_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    session.conn.sendall(chunk)
                    sent_bytes += len(chunk)

            if sent_bytes == file_size:
                print(f"[DOWNLOAD] Success: {sent_bytes} bytes sent for '{rel_path}'")
            else:
                print(f"[DOWNLOAD] Size mismatch. Expected {file_size}, sent {sent_bytes}.")
        except Exception as e:
            print(f"[DOWNLOAD] Error: {e}")

    finally:
        if target_path is not None:
            _clear_busy(target_path)
        elapsed = timer()
        perf.record_transfer(operation="download", bytes_count=sent_bytes, seconds=elapsed, source="server")


def handle_delete(session, line, perf):
    """
    Handle delete request from a client.

    Protocol:
        DELETE <remote_path>

    Where:
        remote_path: Path relative to the user's storage root.
    """
    timer = timed()  # measure delete handling time
    target_path = None
    rel_path = None

    try:
        # Only authenticated clients can delete files.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR DELETE Not authenticated")
            print("[DELETE] denied: client not authenticated")
            return

        parts = line.split()
        if len(parts) != 2:
            _send_line(session.conn, "ERR DELETE Usage: DELETE <remote_path>")
            print("[DELETE] failed: bad syntax")
            return

        _, rel_path = parts[0], parts[1]

        # Resolve the path within the user's storage.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR DELETE Invalid path")
            print(f"[DELETE] failed: invalid path '{rel_path}'")
            return

        # Reserve file for deletion; if it is already in use, reject.
        if not _mark_busy(target_path):
            _send_line(session.conn, "ERR DELETE File is in use")
            print(f"[DELETE] failed: file in use '{target_path}'")
            return

        print(f"[DELETE] request for: {rel_path} -> {target_path}")

        # Check if file exists; send error if missing.
        if not os.path.exists(target_path):
            _send_line(session.conn, f"ERR DELETE File not found: {rel_path}")
            print(f"[DELETE] failed: file not found '{target_path}'")
            return

        # Reject directory deletion here; subfolder removal is handled by SUBFOLDER.
        if not os.path.isfile(target_path):
            _send_line(session.conn, "ERR DELETE Target is not a file")
            print(f"[DELETE] failed: target is not a file '{target_path}'")
            return

        # Remove the file.
        try:
            os.remove(target_path)
            _send_line(session.conn, f"OK DELETE {rel_path}")
            print(f"[DELETE] success: {target_path}")
        except Exception as e:
            _send_line(session.conn, f"ERR DELETE Failed to remove: {rel_path}")
            print(f"[DELETE] error deleting '{target_path}': {e}")

    finally:
        if target_path is not None:
            _clear_busy(target_path)
        elapsed = timer()
        perf.record_response(operation="delete", seconds=elapsed, source="server")


def handle_dir(session, line, perf):
    """
    Handle directory listing request from a client.

    Protocol:
        DIR
        DIR <subpath>

    Where:
        subpath: Optional relative subdirectory under the user's storage root.

    Response:
        BEGIN
          [DIR] name
          [FILE] name
        END
    """
    timer = timed()  # measure dir handling time

    try:
        # Only authenticated clients can view directory listings.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR DIR Not authenticated")
            print("[DIR] denied: client not authenticated")
            return

        parts = line.split(maxsplit=1)
        rel_path = "."
        if len(parts) == 2:
            rel_path = parts[1].strip()

        # Resolve target directory inside user's storage root.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR DIR Invalid path")
            print(f"[DIR] failed: invalid path '{rel_path}'")
            return

        print(f"[DIR] listing for: {target_path}")

        if not os.path.exists(target_path):
            _send_line(session.conn, f"ERR DIR Path not found: {rel_path}")
            print(f"[DIR] failed: path not found '{target_path}'")
            return

        if not os.path.isdir(target_path):
            _send_line(session.conn, "ERR DIR Target is not a directory")
            print(f"[DIR] failed: target is not a directory '{target_path}'")
            return

        try:
            contents = os.listdir(target_path)

            # Send listing to client
            _send_line(session.conn, "BEGIN")

            for item in contents:
                full_path = os.path.join(target_path, item)
                if os.path.isdir(full_path):
                    _send_line(session.conn, f"[DIR] {item}")
                else:
                    _send_line(session.conn, f"[FILE] {item}")

            _send_line(session.conn, "END")

        except OSError as e:
            _send_line(session.conn, "ERR DIR Failed to read directory")
            print(f"[DIR] OS error reading '{target_path}': {e}")
        except Exception as e:
            _send_line(session.conn, "ERR DIR Internal error")
            print(f"[DIR] Unexpected error listing '{target_path}': {e}")

    finally:
        elapsed = timer()
        perf.record_response(operation="dir", seconds=elapsed, source="server")


def handle_subfolder(session, line, perf):
    """
    Handle subfolder management request (create/delete).

    Protocol:
        SUBFOLDER create <path>
        SUBFOLDER delete <path>

    Where:
        path: Relative folder path under the user's storage root.
    """
    timer = timed()  # measure subfolder handling time

    try:
        # Only authenticated clients can manage subfolders.
        if not getattr(session, "authenticated", False):
            _send_line(session.conn, "ERR SUBFOLDER Not authenticated")
            print("[SUBFOLDER] denied: client not authenticated")
            return

        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            _send_line(session.conn, "ERR SUBFOLDER Usage: SUBFOLDER {create|delete} <path>")
            print("[SUBFOLDER] failed: bad syntax")
            return

        _, action, rel_path = parts[0], parts[1].lower(), parts[2].strip()

        if action not in ("create", "delete"):
            _send_line(session.conn, "ERR SUBFOLDER Action must be 'create' or 'delete'")
            print(f"[SUBFOLDER] failed: invalid action '{action}'")
            return

        # Resolve target directory inside user's storage root.
        try:
            target_path = resolve_path(session, rel_path)
        except ValueError:
            _send_line(session.conn, "ERR SUBFOLDER Invalid path")
            print(f"[SUBFOLDER] failed: invalid path '{rel_path}'")
            return

        print(f"[SUBFOLDER] {action} {rel_path} -> {target_path}")

        if action == "create":
            if os.path.exists(target_path):
                if os.path.isdir(target_path):
                    _send_line(session.conn, "ERR SUBFOLDER Directory already exists")
                    print(f"[SUBFOLDER] create failed: directory already exists {target_path}")
                else:
                    _send_line(session.conn, "ERR SUBFOLDER A file with the same name exists at that path")
                    print(f"[SUBFOLDER] create failed: file exists at {target_path}")
                return

            try:
                os.makedirs(target_path, exist_ok=True)
            except OSError:
                _send_line(session.conn, "ERR SUBFOLDER Failed to create directory")
                print(f"[SUBFOLDER] create failed: OS error at {target_path}")
                return

            _send_line(session.conn, f"OK SUBFOLDER CREATE {rel_path}")
            print(f"[SUBFOLDER] created '{target_path}'")
            return

        elif action == "delete":
            if not os.path.exists(target_path):
                _send_line(session.conn, "ERR SUBFOLDER Directory does not exist")
                print(f"[SUBFOLDER] delete failed: directory does not exist {target_path}")
                return

            if not os.path.isdir(target_path):
                _send_line(session.conn, "ERR SUBFOLDER Target is not directory")
                print(f"[SUBFOLDER] delete failed: target is not a directory {target_path}")
                return

            try:
                # Check if directory has contents inside it.
                if os.listdir(target_path):
                    _send_line(session.conn, "ERR SUBFOLDER Directory is not empty")
                    print(f"[SUBFOLDER] delete failed: directory is not empty {target_path}")
                    return
            except OSError as e:
                _send_line(session.conn, "ERR SUBFOLDER Cannot inspect directory")
                print(f"[SUBFOLDER] delete failed: OS error {e}")
                return

            try:
                os.rmdir(target_path)
            except OSError as e:
                _send_line(session.conn, "ERR SUBFOLDER Failed to delete directory")
                print(f"[SUBFOLDER] delete failed while removing directory: {e}")
                return

            _send_line(session.conn, f"OK SUBFOLDER DELETE {rel_path}")
            print(f"[SUBFOLDER] deleted {target_path}")
            return

    finally:
        elapsed = timer()
        perf.record_response(operation="subfolder", seconds=elapsed, source="server")
