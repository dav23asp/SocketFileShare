# server/auth.py
# Handles authentication for login, encryption, and verification of user credentials.

import hashlib      # password key derivation (PBKDF2)
import json         # user database storage (small JSON file)
import os           # filesystem paths and files
import threading    # user DB and key file locking
import hmac         # constant-time compare for password hashes
from cryptography.fernet import Fernet, InvalidToken    # encrypted auth payloads

#### Paths and constants ####
# Base directory of the server package
BASE_DIR = os.path.dirname(__file__)

# All auth-related files live under server/storage/database/
STORAGE_ROOT = os.path.join(BASE_DIR, "storage")
DATABASE_ROOT = os.path.join(STORAGE_ROOT, "database")

# Local JSON-based credential storage and symmetric key file
USER_DB = os.path.join(DATABASE_ROOT, "server_users.json")
SECRET_KEY_FILE = os.path.join(DATABASE_ROOT, "auth_secret.key")

# Project root and client-side locations for the shared key copy.
PROJECT_ROOT = os.path.dirname(BASE_DIR)
CLIENT_STORAGE_ROOT = os.path.join(PROJECT_ROOT, "client", "storage")
CLIENT_DATABASE_ROOT = os.path.join(CLIENT_STORAGE_ROOT, "database")
CLIENT_SECRET_KEY_FILE = os.path.join(CLIENT_DATABASE_ROOT, "auth_secret.key")

ENCODING = "utf-8"

# Password hashing parameters (PBKDF2-HMAC with SHA-256)
SALT_BYTES = 16
PBKDF2_ITERATIONS = 150_000
MIN_PASSWORD_LENGTH = 8

# Known roles (project only needs basic access control)
ROLE_USER = "user"
ROLE_ADMIN = "admin"

# Thread-level locks for user DB and key file access
_USER_DB_LOCK = threading.Lock()
_SECRET_KEY_LOCK = threading.Lock()

#### Utility helpers for paths ####
def _make_dirs(path):
    """
    Create a directory tree if it does not exist.

    This keeps auth data (JSON DB and key) under server/storage/database/.
    """
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

#### Utility setup ####
def init_user_db():
    """
    Create a user database file if it does not exist yet.

    This is a small JSON file that maps username -> user record.
    """
    _make_dirs(DATABASE_ROOT)
    with _USER_DB_LOCK:
        if not os.path.exists(USER_DB):
            print(f"[auth] Creating new user database: {USER_DB}")
            with open(USER_DB, "w", encoding=ENCODING) as db:
                # Start with an empty mapping
                json.dump({}, db)

def init_auth_store():
    """
    Initialize authentication-related storage so that
    the user DB and secret key files exist.

    main.py calls this before the server starts.
    """
    init_user_db()
    _load_or_create_secret_key()

def _load_user_db():
    """
    Load the user database JSON into memory.

    Returns:
        dict: Mapping of username -> user record.
    """
    init_user_db()
    with _USER_DB_LOCK:
        with open(USER_DB, "r", encoding=ENCODING) as db:
            try:
                data = json.load(db)
            except json.JSONDecodeError:
                # If the file is corrupt, start from an empty mapping
                print("[auth] Corrupt user DB; using empty structure")
                data = {}
    if not isinstance(data, dict):
        print("[auth] User DB is not a dict; resetting to empty")
        data = {}
    return data

def _save_user_db(data):
    """
    Save the given user mapping back to the JSON file.

    Parameters:
        data (dict): Mapping of username -> user record.
    """
    _make_dirs(DATABASE_ROOT)
    with _USER_DB_LOCK:
        tmp_path = USER_DB + ".tmp"
        # Write to a temp file first, then atomically replace
        with open(tmp_path, "w", encoding=ENCODING) as db:
            json.dump(data, db, indent=2)
        os.replace(tmp_path, USER_DB)
    print("[auth] User DB saved")

def _generate_user_id():
    """
    Generate a simple numeric user_id string.

    IDs:
      - are numeric strings like "0001", "0002"
      - do not depend on role
      - stay stable for a username

    This scans the existing DB and picks the next free number.
    """
    data = _load_user_db()

    max_num = 0
    # Walk all records and track the highest numeric id
    for rec in data.values():
        if not isinstance(rec, dict):
            continue
        uid = rec.get("user_id")
        if not uid:
            continue
        try:
            num = int(uid)
            if num > max_num:
                max_num = num
        except ValueError:
            # Ignore non-numeric ids
            continue

    # Pad with zeros, 4 digits (e.g., "0001")
    return f"{max_num + 1:04d}"

#### Secret key management (Fernet) ####
def _load_or_create_secret_key():
    """
    Load the shared symmetric key from disk or create one if missing.

    This key is used with Fernet to encrypt small auth payloads,
    so the client never sends passwords in clear text.
    """
    _make_dirs(DATABASE_ROOT)
    with _SECRET_KEY_LOCK:
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, "rb") as f:
                key = f.read().strip()
                if key:
                    return key
                print("[auth] Secret key file empty; creating new key")

        print(f"[auth] Creating new auth secret key: {SECRET_KEY_FILE}")
        key = Fernet.generate_key()

        # Write server copy
        with open(SECRET_KEY_FILE, "wb") as f:
            f.write(key)

        # Try to write a client-side copy under client/storage/database/.
        try:
            os.makedirs(CLIENT_DATABASE_ROOT, exist_ok=True)
            with open(CLIENT_SECRET_KEY_FILE, "wb") as cf:
                cf.write(key)
            print(f"[auth] Wrote client key copy to {CLIENT_SECRET_KEY_FILE}")
        except OSError as exc:
            # Do not block server startup if client copy fails.
            print(f"[auth] Could not write client key copy: {exc}")

        return key

def _get_cipher():
    """
    Create a Fernet cipher instance using the shared secret key.

    Returns:
        Fernet: Cipher object for encryption/decryption.
    """
    key = _load_or_create_secret_key()
    return Fernet(key)

def encrypt_payload(payload_dict):
    """
    Encrypt a small JSON payload for transit.

    Parameters:
        payload_dict (dict): Data to encode and encrypt.

    Returns:
        str: Base64 text token suitable for sending over the socket.
    """
    cipher = _get_cipher()
    raw = json.dumps(payload_dict).encode(ENCODING)
    token = cipher.encrypt(raw)
    return token.decode(ENCODING)

def decrypt_payload(token_str):
    """
    Decrypt a JSON payload received from a client.

    Parameters:
        token_str (str): Base64 text token from client.

    Returns:
        dict: Decoded JSON data.

    Raises:
        InvalidToken: If decryption or verification fails.
        ValueError: If JSON decoding fails.
    """
    cipher = _get_cipher()
    try:
        token_bytes = token_str.encode(ENCODING)
        raw = cipher.decrypt(token_bytes)
        data = json.loads(raw.decode(ENCODING))
        if not isinstance(data, dict):
            # We expect a JSON object, not a list or primitive
            raise ValueError("Decrypted payload is not a JSON object")
        return data
    except InvalidToken:
        print("[auth] Invalid encrypted auth token")
        raise
    except json.JSONDecodeError as exc:
        print("[auth] Decrypted payload is not valid JSON:", exc)
        raise ValueError("Invalid JSON payload") from exc

#### Password hashing ####
def _derive_password_hash(password, salt_bytes):
    """
    Derive a PBKDF2-HMAC hash for the given password and salt.

    Parameters:
        password (str): Plaintext password.
        salt_bytes (bytes): Random salt bytes.

    Returns:
        str: Hex-encoded hash.
    """
    # PBKDF2 slows down brute-force attacks
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(ENCODING),
        salt_bytes,
        PBKDF2_ITERATIONS,
    )
    return key.hex()

def _check_password_policy(password):
    """
    Apply a minimal password policy.

    Parameters:
        password (str): Candidate plaintext password.

    Raises:
        ValueError: If the password does not meet policy.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")

def hash_password(password):
    """
    Hash a password using PBKDF2-HMAC for storage and comparison.

    Parameters:
        password (str): Plaintext password from user input.

    Returns:
        tuple: (salt_hex, hash_hex)
    """
    _check_password_policy(password)
    # Generate a random salt for this password
    salt = os.urandom(SALT_BYTES)
    pwd_hash = _derive_password_hash(password, salt)
    salt_hex = salt.hex()
    return salt_hex, pwd_hash

def verify_password(password, salt_hex, stored_hash_hex):
    """
    Check a candidate password against stored salt and hash.

    Parameters:
        password (str): Candidate plaintext password.
        salt_hex (str): Stored salt as hex string.
        stored_hash_hex (str): Stored password hash as hex string.

    Returns:
        bool: True if the hash matches, False otherwise.
    """
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        print("[auth] Invalid salt in user DB")
        return False

    computed_hash = _derive_password_hash(password, salt)
    # Use constant-time comparison to reduce timing side channels
    return hmac.compare_digest(computed_hash, stored_hash_hex)

#### User management ####
def register_user(username, password, role=ROLE_USER, overwrite=False):
    """
    Register a new user with hashed password.

    Parameters:
        username (str): Username to register.
        password (str): Plaintext password.
        role     (str): ROLE_USER or ROLE_ADMIN.
        overwrite (bool): If True, replace an existing user entry.

    Returns:
        dict: Newly created or updated user record.

    Raises:
        ValueError: If input is invalid or user exists and overwrite is False.
    """
    if role not in (ROLE_USER, ROLE_ADMIN):
        raise ValueError(f"Invalid role: {role}")
    if not isinstance(username, str) or not username:
        raise ValueError("Username must be a non-empty string")

    data = _load_user_db()

    if username in data and not overwrite:
        raise ValueError(f"User '{username}' already exists")

    salt_hex, pwd_hash = hash_password(password)

    # If the user already exists and we are overwriting, keep the same id.
    if username in data and overwrite:
        user_id = data[username].get("user_id")
    else:
        user_id = _generate_user_id()

    user_record = {
        "username": username,
        "user_id": user_id,
        "role": role,
        "salt": salt_hex,
        "password_hash": pwd_hash,
    }
    data[username] = user_record
    _save_user_db(data)
    print(f"[auth] Registered user '{username}' with role '{role}' and id '{user_id}'")
    return user_record

def delete_user(username):
    """
    Remove a user from the user database.

    Parameters:
        username (str): Username to delete.

    Returns:
        bool: True if user existed and was removed, False if user was missing.
    """
    data = _load_user_db()
    if username not in data:
        print(f"[auth] delete_user: '{username}' does not exist")
        return False

    # At this layer we only remove auth info; storage cleanup can live in server-side code.
    del data[username]
    _save_user_db(data)
    print(f"[auth] Deleted user '{username}'")
    return True

def reset_password(username, new_password):
    """
    Reset a user's password to a new value.

    Parameters:
        username (str): Username whose password will change.
        new_password (str): New plaintext password.

    Returns:
        bool: True if user exists and password changed, False otherwise.
    """
    data = _load_user_db()
    record = data.get(username)
    if not record:
        print(f"[auth] reset_password: '{username}' does not exist")
        return False

    salt_hex, pwd_hash = hash_password(new_password)
    record["salt"] = salt_hex
    record["password_hash"] = pwd_hash
    data[username] = record
    _save_user_db(data)
    print(f"[auth] Password reset for user '{username}'")
    return True

def set_role(username, new_role):
    """
    Change a user's role.

    Parameters:
        username (str): Username to change.
        new_role (str): ROLE_USER or ROLE_ADMIN.

    Returns:
        bool: True if user exists and role changed, False otherwise.
    """
    if new_role not in (ROLE_USER, ROLE_ADMIN):
        raise ValueError(f"Invalid role: {new_role}")

    data = _load_user_db()
    record = data.get(username)
    if not record:
        print(f"[auth] set_role: '{username}' does not exist")
        return False

    # Only the role field changes; user_id stays stable.
    record["role"] = new_role
    data[username] = record
    _save_user_db(data)
    print(f"[auth] Role for '{username}' changed to '{new_role}'")
    return True

def get_user(username):
    """
    Fetch a user record by username.

    Parameters:
        username (str): Username to look up.

    Returns:
        dict or None: User record or None if not found.
    """
    data = _load_user_db()
    return data.get(username)

def list_users():
    """
    Get a snapshot of current users.

    Returns:
        list: List of user records (dicts).
    """
    data = _load_user_db()
    return list(data.values())

def verify_credentials(username, password):
    """
    Verify login credentials for an incoming client connection.

    Parameters:
        username (str): Username attempting to log in.
        password (str): Plaintext password provided by client.

    Returns:
        tuple:
            bool: True if credentials are valid.
            dict or None: User record on success, None on failure.
    """
    data = _load_user_db()
    record = data.get(username)
    if not record:
        print(f"[auth] verify_credentials: user '{username}' not found")
        return False, None

    salt_hex = record.get("salt")
    stored_hash = record.get("password_hash")
    if not salt_hex or not stored_hash:
        print(f"[auth] verify_credentials: user '{username}' missing salt/hash")
        return False, None

    if verify_password(password, salt_hex, stored_hash):
        print(f"[auth] verify_credentials: user '{username}' authenticated")
        return True, record

    print(f"[auth] verify_credentials: invalid password for '{username}'")
    return False, None

#### Socket helpers ####
def _recv_line(conn, max_bytes=4096):
    """
    Read a single line (terminated by '\\n') from a socket.

    This protects against partial reads and overly long input.

    Parameters:
        conn (socket.socket): Connected socket.
        max_bytes (int): Hard cap on bytes to read.

    Returns:
        str or None: Line without trailing newline, or None if connection closed.

    Raises:
        ValueError: If input exceeds max_bytes without newline.
    """
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = conn.recv(1024)
        if not chunk:
            # Remote side closed connection
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
    return line.decode(ENCODING, errors="replace").strip()

#### Connection-level handler ####
def handle_auth(conn, addr):
    """
    Handle a login authentication request from a connected client.

    Protocol:
        Client sends a single line:
            AUTH <token>\\n

        Where <token> is a Fernet-encrypted JSON payload:
            {
                "op": "login",
                "username": "...",
                "password": "..."
            }

        On success:
            Server replies:
                OK AUTH role=<role> user_id=<user_id>\\n

        On failure:
            Server replies:
                ERR AUTH <reason>\\n

    Parameters:
        conn (socket.socket): Active client connection.
        addr (tuple): Client address.

    Returns:
        tuple:
            bool: True if login succeeded, False otherwise.
            dict or None: User record when login succeeds, None otherwise.
    """
    try:
        line = _recv_line(conn)
        if line is None:
            print(f"[auth] No data from {addr}; closing auth")
            conn.sendall(b"ERR AUTH No data received\n")
            return False, None

        if not line.startswith("AUTH "):
            print(f"[auth] Invalid auth command from {addr}")
            conn.sendall(b"ERR AUTH Invalid auth command\n")
            return False, None

        _, token_str = line.split(" ", 1)

        try:
            payload = decrypt_payload(token_str)
        except InvalidToken:
            # Ciphertext could not be verified; drop login
            conn.sendall(b"ERR AUTH Invalid token\n")
            return False, None
        except ValueError:
            # JSON payload was malformed
            conn.sendall(b"ERR AUTH Invalid payload\n")
            return False, None

        op = payload.get("op", "login")
        if op != "login":
            print(f"[auth] Unsupported auth op from {addr}")
            conn.sendall(b"ERR AUTH Unsupported operation\n")
            return False, None

        username = payload.get("username")
        password = payload.get("password")
        if not username or not password:
            conn.sendall(b"ERR AUTH Missing username or password\n")
            return False, None

        ok, record = verify_credentials(username, password)
        if not ok or record is None:
            conn.sendall(b"ERR AUTH Invalid credentials\n")
            return False, None

        role = record.get("role", ROLE_USER)
        user_id = record.get("user_id", "")
        # Only send role and id, not any secret data
        response = f"OK AUTH role={role} user_id={user_id}\n"
        conn.sendall(response.encode(ENCODING))
        return True, record

    except ValueError as exc:
        print(f"[auth] Protocol error during auth for {addr}: {exc}")
        try:
            conn.sendall(b"ERR AUTH Protocol error\n")
        except Exception:
            pass
        return False, None
    except ConnectionError as exc:
        print(f"[auth] Connection error during auth for {addr}: {exc}")
        return False, None
    except Exception as exc:
        print(f"[auth] Unexpected error during auth for {addr}: {exc}")
        try:
            conn.sendall(b"ERR AUTH Server error\n")
        except Exception:
            pass
        return False, None
