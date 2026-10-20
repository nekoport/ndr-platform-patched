"""SQLAlchemy setup (PostgreSQL in production, SQLite for tests)."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import config


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    if url.startswith("sqlite"):
        if ":memory:" in url or url == "sqlite://":
            # single shared connection so in-memory tables persist across sessions
            return create_engine(url, connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
        return create_engine(url, connect_args={"check_same_thread": False},
                             pool_pre_ping=True)
    return create_engine(url, pool_pre_ping=True, pool_size=10,
                         max_overflow=10)


engine = _make_engine(config.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
