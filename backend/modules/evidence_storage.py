"""
Evidence Storage Module
=======================
Stores investigation data in SQLite database:
- Case ID
- Evidence file name
- Hash (SHA256)
- Timestamp
- Investigator name
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


# Default database path (relative to project root)
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "database" / "forensics.db"


def get_connection(db_path: Optional[str] = None):
    """Get SQLite connection and ensure tables exist."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
    _init_tables(conn)
    return conn


def _init_tables(conn: sqlite3.Connection) -> None:
    """Create evidence and cases tables if they do not exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_name TEXT,
            investigator_name TEXT,
            created_at TEXT,
            status TEXT DEFAULT 'open'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT,
            hash_md5 TEXT,
            hash_sha1 TEXT,
            hash_sha256 TEXT,
            timestamp_collected TEXT,
            investigator_name TEXT,
            evidence_type TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            time_str TEXT,
            event_description TEXT,
            source TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    """)
    conn.commit()


def create_case(case_id: str, case_name: str, investigator_name: str, db_path: Optional[str] = None) -> bool:
    """Create a new investigation case."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO cases (case_id, case_name, investigator_name, created_at, status) VALUES (?, ?, ?, ?, 'open')",
            (case_id, case_name, investigator_name, datetime.now().isoformat()),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def add_evidence(
    case_id: str,
    file_name: str,
    file_path: Optional[str] = None,
    hash_md5: Optional[str] = None,
    hash_sha1: Optional[str] = None,
    hash_sha256: Optional[str] = None,
    investigator_name: Optional[str] = None,
    evidence_type: Optional[str] = None,
    db_path: Optional[str] = None,
) -> bool:
    """Add an evidence record to the database."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """INSERT INTO evidence (case_id, file_name, file_path, hash_md5, hash_sha1, hash_sha256, timestamp_collected, investigator_name, evidence_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_id,
                file_name,
                file_path,
                hash_md5,
                hash_sha1,
                hash_sha256,
                datetime.now().isoformat(),
                investigator_name or "",
                evidence_type or "file",
            ),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def get_evidence_by_case(case_id: str, db_path: Optional[str] = None) -> list:
    """Get all evidence records for a case."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY timestamp_collected DESC",
            (case_id,),
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_case(case_id: str, db_path: Optional[str] = None) -> Optional[dict]:
    """Get case details by case_id."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_cases(db_path: Optional[str] = None) -> list:
    """Get all cases."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def add_timeline_event(case_id: str, time_str: str, event_description: str, source: str = "log", db_path: Optional[str] = None) -> bool:
    """Add a timeline event for a case."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO timeline_events (case_id, time_str, event_description, source) VALUES (?, ?, ?, ?)",
            (case_id, time_str, event_description, source),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def get_timeline_events(case_id: str, db_path: Optional[str] = None) -> list:
    """Get all timeline events for a case, sorted by time."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute(
            "SELECT time_str, event_description, source FROM timeline_events WHERE case_id = ? ORDER BY id",
            (case_id,),
        )
        return [{"time_str": r[0], "event": r[1], "source": r[2]} for r in cur.fetchall()]
    finally:
        conn.close()
