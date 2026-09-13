"""Shared pytest configuration.

Every test runs against a throwaway SQLite database in a temp directory so
the suite never touches your real data/ folder, and is safe to run in
parallel with a live gateway.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def isolated_environment(tmp_path_factory):
    root = tmp_path_factory.mktemp("chronodns-test")
    os.environ["CHRONODNS_DB_BACKEND"] = "sqlite"
    os.environ["CHRONODNS_SQLITE_PATH"] = str(root / "test.db")
    os.environ["CHRONODNS_MODEL_DIR"] = str(root / "models")
    os.environ["CHRONODNS_LOG_LEVEL"] = "ERROR"
    os.environ["CHRONODNS_LOG_FILE"] = str(root / "test.log")
    Path(os.environ["CHRONODNS_MODEL_DIR"]).mkdir(parents=True, exist_ok=True)

    from chronodns.config import get_config
    get_config(reload=True)
    yield root


@pytest.fixture(autouse=True)
def fresh_config():
    """Reload config between tests so threshold tweaks never leak."""
    from chronodns.config import get_config
    get_config(reload=True)
    yield
