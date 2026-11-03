"""
db/models.py
SQLite persistence layer for threat telemetry, blocked entities, and vulnerability audits.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path("db/waf_portal.db").resolve()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Initializes normalized tables for incidents, audit scans, and active rule toggles."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table 1: Recorded WAF security events & blocked attacks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            payload_sample TEXT,
            endpoint TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    # Table 2: Vulnerability audit scans against target web systems
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target_url TEXT NOT NULL,
            security_score INTEGER NOT NULL,
            findings_json TEXT NOT NULL
        )
    """)

    # Table 3: WAF Active Defense Toggle configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waf_config (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        )
    """)

    # Default toggles: 1 = Active / Block, 0 = Monitor only
    default_configs = [
        ("block_sqli", 1),
        ("block_xss", 1),
        ("block_traversal", 1),
        ("block_scanners", 1),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO waf_config (key, value) VALUES (?, ?)",
        default_configs,
    )

    conn.commit()
    conn.close()