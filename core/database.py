import sqlite3
import threading
from datetime import datetime, timezone


class ForensicDatabase:
    """Thread-safe SQLite persistence for trusted bindings and attack audit logs."""

    def __init__(self, db_path: str = "arpguard_audit.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trusted_hosts (
                    ip_address TEXT PRIMARY KEY,
                    mac_address TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_verified TEXT NOT NULL,
                    is_gateway INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    legitimate_mac TEXT NOT NULL,
                    attacker_mac TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitigated INTEGER NOT NULL
                )
            """)
            conn.commit()

    def upsert_trusted_host(self, ip: str, mac: str, is_gateway: int = 0) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO trusted_hosts (ip_address, mac_address, first_seen, last_verified, is_gateway)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_verified = excluded.last_verified,
                    is_gateway = MAX(trusted_hosts.is_gateway, excluded.is_gateway)
            """,
                (ip, mac.lower(), now, now, is_gateway),
            )
            conn.commit()

    def log_incident(
        self,
        alert_type: str,
        ip: str,
        real_mac: str,
        fake_mac: str,
        severity: str,
        mitigated: bool,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO security_incidents
                (timestamp, alert_type, target_ip, legitimate_mac, attacker_mac, severity, mitigated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    now,
                    alert_type,
                    ip,
                    real_mac.lower(),
                    fake_mac.lower(),
                    severity,
                    int(mitigated),
                ),
            )
            conn.commit()

    def fetch_recent_incidents(self, limit: int = 10) -> list[tuple]:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT incident_id, timestamp, alert_type, target_ip, legitimate_mac, attacker_mac, severity, mitigated
                FROM security_incidents
                ORDER BY incident_id DESC
                LIMIT ?
            """,
                (limit,),
            )
            return cursor.fetchall()
