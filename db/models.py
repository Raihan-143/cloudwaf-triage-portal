import sqlite3
from pathlib import Path

DB_PATH = Path("db/waf_portal.db").resolve()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Initializes normalized tables for incidents, audit scans, blacklist, and active rules."""
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

    # Table 3: Active Defense Configuration & Virtual Patching flags
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waf_config (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        )
    """)

    # Table 4: Permanent IP Blacklist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    default_configs = [
        ("virtual_patch_headers", 0),  # 1 = Injects hardening headers on all responses
        ("strict_mode", 1),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO waf_config (key, value) VALUES (?, ?)",
        default_configs,
    )

    conn.commit()
    conn.close()