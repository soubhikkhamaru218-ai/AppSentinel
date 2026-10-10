from pathlib import Path

from backend.models.database import build_engine_options


def test_sqlite_database_url_resolves_relative_path():
    url, connect_args = build_engine_options("sqlite:///./storage/test_config.db")

    assert url.drivername == "sqlite"
    assert Path(url.database).is_absolute()
    assert url.database.endswith(str(Path("storage/test_config.db")))
    assert connect_args == {"check_same_thread": False}


def test_postgresql_url_uses_psycopg_driver_without_sqlite_args():
    url, connect_args = build_engine_options("postgresql://user:pass@example.com:5432/appsentinel")

    assert url.drivername == "postgresql+psycopg"
    assert url.host == "example.com"
    assert url.database == "appsentinel"
    assert connect_args == {}


def test_legacy_postgres_url_alias_is_supported():
    url, connect_args = build_engine_options("postgres://user:pass@example.com/appsentinel")

    assert url.drivername == "postgresql+psycopg"
    assert connect_args == {}
