"""Fixtures partagées pour les tests."""

import os
import tempfile

import pytest

from src.config.settings import get_settings
from src.core.storage import SecureStorage
from src.web.dependencies import get_managers


@pytest.fixture
def temp_storage(tmp_path, monkeypatch):
    """Stockage isolé dans un répertoire temporaire."""
    storage_path = str(tmp_path / "certmanager")
    monkeypatch.setenv("CERTMANAGER_STORAGE_PATH", storage_path)
    get_settings.cache_clear()
    get_managers.cache_clear()
    return SecureStorage(storage_path=storage_path)


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """Client FastAPI avec stockage temporaire et auth désactivée."""
    storage_path = str(tmp_path / "certmanager")
    monkeypatch.setenv("CERTMANAGER_STORAGE_PATH", storage_path)
    monkeypatch.setenv("CERTMANAGER_AUTH_ENABLED", "false")
    monkeypatch.setenv("CERTMANAGER_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("CERTMANAGER_ENCRYPT_KEYS", "false")
    get_settings.cache_clear()
    get_managers.cache_clear()

    from fastapi.testclient import TestClient
    from src.web.app import create_app

    with TestClient(create_app()) as client:
        yield client

    get_settings.cache_clear()
    get_managers.cache_clear()


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Environnement isolé pour les tests CLI."""
    storage_path = str(tmp_path / "certmanager")
    monkeypatch.setenv("CERTMANAGER_STORAGE_PATH", storage_path)
    monkeypatch.setenv("CERTMANAGER_AUTH_ENABLED", "false")
    monkeypatch.setenv("CERTMANAGER_ENCRYPT_KEYS", "false")
    get_settings.cache_clear()
    yield storage_path
    get_settings.cache_clear()


@pytest.fixture
def cli_runner(cli_env):
    """Runner Click avec stockage temporaire."""
    from click.testing import CliRunner
    from src.cli.commands import cli

    runner = CliRunner()
    return runner, cli
