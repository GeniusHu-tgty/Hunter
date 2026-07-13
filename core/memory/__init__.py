"""Persistent target intelligence and technique effectiveness memory."""

import sqlite3
from pathlib import Path

from .fingerprint_database import FingerprintDatabase
from .pattern_engine import PatternEngine
from .target_memory import DEFAULT_DB_PATH, TargetMemory
from .technique_memory import TechniqueMemory


def reset_memory(db_path: str | Path = DEFAULT_DB_PATH) -> dict[str, str]:
    """Atomically clear all memory tables while preserving their schema."""

    database_path = Path(db_path).expanduser().resolve()
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for table in (
            "technique_stats",
            "technique_attempts",
            "techniques",
            "attack_history",
            "vulnerabilities",
            "endpoints",
            "fingerprints",
            "targets",
        ):
            connection.execute(f"DELETE FROM {table}")
    return {"database_path": str(database_path), "status": "reset"}


__all__ = [
    "FingerprintDatabase",
    "PatternEngine",
    "reset_memory",
    "TargetMemory",
    "TechniqueMemory",
]
