"""
SQLAlchemy database setup, connection pooling, and session management for PostgreSQL.
"""
import logging
from typing import Dict, Any, Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.exc import OperationalError
from fastapi import HTTPException, status
from backend.config import settings

logger = logging.getLogger("database")

def create_db_engine():
    db_url = settings.database_url
    if "postgresql" in db_url:
        return create_engine(
            db_url,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=300
        )
    elif "sqlite" in db_url:
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False}
        )
    else:
        return create_engine(db_url)

engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def check_db_connection() -> Dict[str, Any]:
    """Test connection to the database without throwing uncaught exceptions."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "connected": True,
            "dialect": engine.url.drivername,
            "database": engine.url.database or settings.db_name
        }
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return {
            "connected": False,
            "error": str(e),
            "dialect": engine.url.drivername
        }

def get_db() -> Generator[Session, None, None]:
    """FastAPI Dependency for obtaining database sessions with graceful error handling."""
    db = None
    try:
        db = SessionLocal()
        yield db
    except OperationalError as oe:
        logger.error(f"PostgreSQL Operational Error: {oe}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable. Please ensure PostgreSQL is running and check connection configuration."
        )
    finally:
        if db:
            db.close()

