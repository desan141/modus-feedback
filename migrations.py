"""Add nullable authors to the old SQLite schema; never assign legacy authors.

The online SQLite backup API also works when the old application has the DB open.
All original columns and rows remain unchanged. This module uses only stdlib.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def migrate_database(path: Path) -> Path | None:
    if not path.exists():
        return None
    with sqlite3.connect(path, timeout=30) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version > 2:
            raise RuntimeError("Версия базы новее приложения; миграция остановлена")
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "tickets" not in tables:
            return None
        additions = []
        for table in ("tickets", "comments"):
            if table in tables:
                columns = {r[1] for r in connection.execute(f"PRAGMA table_info({table})")}
                if "author_id" not in columns:
                    additions.append(table)
        needs_migration = bool(additions) or not {"users", "auth_sessions", "ticket_events", "app_meta", "notifications"}.issubset(tables)
        if not needs_migration:
            return None
        backup_dir = path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_path = backup_dir / f"{path.stem}-pre-auth-{stamp}.db"
        with sqlite3.connect(backup_path) as backup:
            connection.backup(backup)
        connection.execute("BEGIN IMMEDIATE")
        try:
            for table in additions:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN author_id INTEGER REFERENCES users(id)")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return backup_path
