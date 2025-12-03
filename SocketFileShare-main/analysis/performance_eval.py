# analysis/performance_eval.py
# Collects data rates, transfer times, and response times for performance analysis.

import time         # high-resolution timing
import threading    # thread-safe metrics
import csv          # CSV export of metrics for offline analysis
import json         # serialize metadata for CSV storage

#### Simple Timer ####
def timed():
    """
    Return a function that yields elapsed seconds when called.

    Usage:
        timer = timed()
        ... do work ...
        elapsed = timer()

    This helper is used throughout the project to measure:
      - Upload/download transfer times
      - Command round-trip latency (auth, dir, delete, subfolder, etc.)
      - Session duration and server uptime
    """
    start = time.perf_counter()  # monotonic, high-resolution clock

    def end():
        """Return elapsed seconds since the timer was created."""
        return time.perf_counter() - start

    return end

#### Metric Recorder ####
class PerfRecorder:
    """
    Thread-safe, in-memory performance data recorder.

    Each record has:
      - operation: str
          e.g. 'upload', 'download', 'auth', 'dir', 'delete',
               'subfolder', 'session', 'server_uptime', 'client_session'
      - bytes: int
          Number of bytes transferred (0 for non-transfer operations)
      - seconds: float
          Duration in seconds
      - rate_MBps: float or None
          Data rate in megabytes per second (for transfer operations)
      - source: str
          Label for origin, e.g. 'server' or 'client'
      - timestamp: float
          UNIX timestamp (seconds since epoch)
      - meta: dict or other (optional)
          Extra context (e.g., filename, command name, user_id)
    """

    def __init__(self):
        # Protects the shared list of records when used from multiple threads
        self._lock = threading.Lock()
        # Internal list of measurement dictionaries
        self._records = []

    def _add_record(self, record):
        """
        Append a record in a thread-safe way.

        Parameters:
            record (dict): Populated measurement dictionary.
        """
        with self._lock:
            self._records.append(record)

    def record_transfer(self, *, operation, bytes_count, seconds, source="server", meta=None):
        """
        Record an upload or download measurement.

        Parameters:
            operation   (str): Operation name ('upload' or 'download').
            bytes_count (int): Bytes transferred during the operation.
            seconds   (float): Duration in seconds.
            source     (str): Label for origin, e.g. 'server' or 'client'.
            meta       (dict|any|None): Optional extra info (e.g., filename).

        This is designed to be called from:
          - server.file_ops.handle_upload / handle_download
          - client.commands.upload / download

        Example:
            timer = timed()
            ... do upload ...
            elapsed = timer()
            perf.record_transfer(
                operation="upload",
                bytes_count=file_size,
                seconds=elapsed,
                source="server",
                meta={"filename": "bigfile.bin"}
            )
        """
        # Avoid division by zero; a failed or zero-duration transfer has no rate.
        rate = (bytes_count / (1024 * 1024)) / seconds if seconds > 0 else None

        record = {
            "operation": operation,
            "bytes": int(bytes_count),
            "seconds": float(seconds),
            "rate_MBps": float(rate) if rate is not None else None,
            "source": source,
            "timestamp": time.time(),
        }

        if meta is not None:
            # Copy dict metadata or store other types as-is for later export.
            if isinstance(meta, dict):
                record["meta"] = dict(meta)
            else:
                record["meta"] = meta

        # Store this transfer measurement for later offline analysis.
        self._add_record(record)

    def record_response(self, *, operation, seconds, source="server", meta=None):
        """
        Record a non-transfer operation (no direct byte count).

        Parameters:
            operation (str): Operation name, e.g. 'auth', 'dir', 'delete',
                             'subfolder', 'session', 'server_uptime',
                             'client_session'.
            seconds (float): Duration in seconds.
            source   (str): Label for origin, e.g. 'server' or 'client'.
            meta     (dict|any|None): Optional extra info (e.g., command name).

        Typical usage:
          - After auth handshake completes (server side):  operation='auth'
          - After DIR/DELETE/SUBFOLDER completes:          operation='dir', 'delete', 'subfolder'
          - At end of a client session:                    operation='session' or 'client_session'
          - When server shuts down:                        operation='server_uptime'
        """
        record = {
            "operation": operation,
            "bytes": 0,                # Non-transfer measurements do not track bytes.
            "seconds": float(seconds),
            "rate_MBps": None,         # Not applicable for non-transfer ops.
            "source": source,
            "timestamp": time.time(),
        }

        if meta is not None:
            # Copy dict metadata or store other types as-is for later export.
            if isinstance(meta, dict):
                record["meta"] = dict(meta)
            else:
                record["meta"] = meta

        # Store this response-time measurement for offline analysis.
        self._add_record(record)

    def snapshot(self):
        """
        Return a copy of all stored records for offline review.

        Returns:
            list[dict]: List of metric records.

        This satisfies the project requirement that statistics must be
        stored (e.g., as a dictionary or list of dicts) for later analysis.
        """
        with self._lock:
            # Return a shallow copy to avoid external mutation of internal list.
            return list(self._records)

    def clear(self):
        """
        Remove all stored records.

        This can be used between test runs or experiments so old data
        does not mix with new metrics.
        """
        with self._lock:
            self._records.clear()

    def to_csv(self, filepath):
        """
        Write current metrics to a CSV file for offline analysis.

        Parameters:
            filepath (str): Path to CSV file to write.

        The CSV will contain one row per record, with columns including:
            operation, bytes, seconds, rate_MBps, source, timestamp, meta

        The 'meta' column (if present) will be stored as a string so tools
        can parse it later (for example, JSON if it started as a dict).
        """
        data = self.snapshot()

        # If there are no records yet, still create a header row with common fields.
        if not data:
            fieldnames = ["operation", "bytes", "seconds", "rate_MBps", "source", "timestamp", "meta"]
        else:
            # Collect the union of keys across all records to avoid dropping any fields.
            fieldnames = set()
            for rec in data:
                fieldnames.update(rec.keys())
            fieldnames = list(fieldnames)

        with open(filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in data:
                # Create a shallow copy to allow field adjustments before writing to CSV.
                row = dict(rec)

                # Convert dict metadata to a JSON string for easier offline parsing.
                if "meta" in row and isinstance(row["meta"], dict):
                    try:
                        row["meta"] = json.dumps(row["meta"], sort_keys=True)
                    except TypeError:
                        # Fallback to plain string if JSON encoding fails.
                        row["meta"] = str(row["meta"])

                writer.writerow(row)
