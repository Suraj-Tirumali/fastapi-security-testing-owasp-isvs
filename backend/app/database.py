# -----------------------------
# SQLAlchemy and environment setup
# -----------------------------
from sqlalchemy import create_engine                   # Core DB engine
from sqlalchemy.orm import sessionmaker, Session       # ORM session management
from sqlalchemy.ext.declarative import declarative_base  # Base class for models
import os
from dotenv import load_dotenv                         # Load environment variables from .env

# -----------------------------
# Load environment variables (e.g., DATABASE_URL)
# -----------------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")               # Get DB URL from .env

# -----------------------------
# Create SQLAlchemy engine
# -----------------------------
engine = create_engine(DATABASE_URL)                   # Engine connects SQLAlchemy to the database

# -----------------------------
# Create a session factory
# -----------------------------
SessionLocal = sessionmaker(
    autocommit=False,                                  # Manual control over commit
    autoflush=False,                                   # Prevent automatic flush to DB
    bind=engine                                        # Bind session to engine
)

# -----------------------------
# Base class for all ORM models
# -----------------------------
Base = declarative_base()                              # All models will inherit from this

# -----------------------------
# Dependency: Provide DB session to route handlers
# -----------------------------
def get_db():
    db: Session = SessionLocal()                       # Create new session
    try:
        yield db                                       # Yield session for use in request
    finally:
        db.close()                                     # Ensure session is closed after request