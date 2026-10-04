"""SQLite-backed scan history."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.models import ScanResult
from app.utils import DATA_DIR


class HistoryStore:
    """Persist scan summaries and complete raw scan JSON locally."""

    def __init__(self, db_path: Path | None = None) -> None:
        DATA_DIR.mkdir(exist_ok=True)
        self.db_path = db_path or DATA_DIR / "history.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection."""

        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        """Create tables when the app is launched for the first time."""

        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    rating TEXT NOT NULL,
                    certificate_status TEXT NOT NULL,
                    weak_configuration INTEGER NOT NULL,
                    raw_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")

    def save(self, result: ScanResult) -> None:
        """Save a completed scan."""

        critical_cert = any(item.title in {"Expired certificate", "Invalid hostname", "Untrusted issuer"} for item in result.findings)
        cert_status = "Problem" if critical_cert else "Valid"
        weak_config = int(any(item.severity in {"CRITICAL", "HIGH"} for item in result.findings))

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (scanned_at, domain, score, rating, certificate_status, weak_configuration, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scanned_at,
                    result.domain,
                    result.score.total,
                    result.overall_rating,
                    cert_status,
                    weak_config,
                    json.dumps(result.to_dict(), indent=2),
                ),
            )

    def list(self, search: str = "") -> list[dict[str, Any]]:
        """Return history rows, newest first."""

        params: tuple[Any, ...] = ()
        where = ""
        if search.strip():
            where = "WHERE domain LIKE ?"
            params = (f"%{search.strip()}%",)

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT id, scanned_at, domain, score, rating, certificate_status, weak_configuration
                FROM scans
                {where}
                ORDER BY id DESC
                LIMIT 500
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard(self) -> dict[str, Any]:
        """Return dashboard aggregate metrics."""

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_scans,
                    COALESCE(ROUND(AVG(score), 1), 0) AS average_score,
                    SUM(CASE WHEN certificate_status = 'Problem' THEN 1 ELSE 0 END) AS expired_certificates,
                    SUM(weak_configuration) AS weak_configurations,
                    SUM(CASE WHEN score >= 90 THEN 1 ELSE 0 END) AS secure_websites
                FROM scans
                """
            ).fetchone()
        return {
            "total_scans": row[0] or 0,
            "average_score": row[1] or 0,
            "expired_certificates": row[2] or 0,
            "weak_configurations": row[3] or 0,
            "secure_websites": row[4] or 0,
        }

