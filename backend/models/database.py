"""
AppSentinel // Database Engine & Session Management
SQLAlchemy-backed scan history persistence.
"""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import sessionmaker, declarative_base

from backend.config import PROJECT_ROOT, get_settings

settings = get_settings()


def build_engine_options(database_url: str) -> tuple[URL, dict[str, object]]:
    """
    Convert the configured DATABASE_URL into a SQLAlchemy URL and connect args.

    SQLite remains the default for local development. PostgreSQL URLs from common
    hosts are normalized to the psycopg v3 dialect so production can use hosted
    Postgres without changing application code.
    """
    url = make_url(database_url)
    drivername = url.drivername.lower()
    connect_args: dict[str, object] = {}

    if drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+psycopg")
    elif drivername.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if url.database and url.database != ":memory:":
            db_path = Path(url.database)
            if not db_path.is_absolute():
                db_path = PROJECT_ROOT / db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            url = url.set(database=str(db_path))

    return url, connect_args


database_url, connect_args = build_engine_options(settings.database_url)

engine = create_engine(
    database_url,
    connect_args=connect_args,
    echo=settings.is_dev,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_database_file_path() -> Path | None:
    """Return the SQLite database file path, or None for non-file databases."""
    if engine.url.drivername.startswith("sqlite") and engine.url.database and engine.url.database != ":memory:":
        return Path(engine.url.database)
    return None


def get_db():
    """
    FastAPI dependency that provides a database session.
    Auto-closes on request completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist."""
    from backend.models import result_models  # noqa: F401 - registers tables with Base.metadata
    Base.metadata.create_all(bind=engine)
