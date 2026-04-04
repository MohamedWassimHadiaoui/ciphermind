"""
Audit Logger - Records every AI decision and human action.

WHY THIS EXISTS:
The hackathon requires "traçabilité totale" (total traceability).
Every time the AI makes a decision or a human approves/rejects something,
we log it to a SQLite database so it can be audited later.

This is critical for the 30% "Human Control & Explainability" score.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone


# Path to our SQLite database file
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "audit.db")


def get_db_connection():
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    # Return rows as dictionaries instead of tuples (easier to work with)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create the audit_logs table if it doesn't exist.
    Called once when the app starts.
    """
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            analysis_id TEXT,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            metadata TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_event(analysis_id: str, event_type: str, actor: str, action: str,
              details: str = "", metadata: dict = None):
    """
    Log an event to the audit database.

    Parameters:
    - analysis_id: Links the log to a specific phishing analysis
    - event_type: Category like "analysis", "remediation", "human_decision"
    - actor: Who did it - "ai_engine" or "human_operator"
    - action: What happened - "phishing_detected", "action_approved", etc.
    - details: Human-readable description of what happened
    - metadata: Extra JSON data (confidence scores, feature details, etc.)
    """
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO audit_logs (timestamp, analysis_id, event_type, actor, action, details, metadata)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            analysis_id,
            event_type,
            actor,
            action,
            details,
            json.dumps(metadata) if metadata else None
        )
    )
    conn.commit()
    conn.close()


def get_logs(analysis_id: str = None, limit: int = 100) -> list:
    """
    Retrieve audit logs, optionally filtered by analysis_id.
    Returns the most recent logs first.
    """
    conn = get_db_connection()

    if analysis_id:
        rows = conn.execute(
            "SELECT * FROM audit_logs WHERE analysis_id = ? ORDER BY id DESC LIMIT ?",
            (analysis_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()

    conn.close()

    # Convert sqlite3.Row objects to plain dictionaries
    logs = []
    for row in rows:
        log = dict(row)
        # Parse the metadata JSON string back into a dictionary
        if log.get("metadata"):
            try:
                log["metadata"] = json.loads(log["metadata"])
            except json.JSONDecodeError:
                pass
        logs.append(log)

    return logs
