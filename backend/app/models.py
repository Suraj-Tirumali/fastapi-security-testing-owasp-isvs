# Import required modules for datetime and SQLAlchemy ORM
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

# -----------------------------
# Resource Table
# -----------------------------
class Resource(Base):
    __tablename__ = "resources"  # Table name in DB

    resource_id = Column(String(12), primary_key=True, unique=True)  # Unique resource identifier
    category = Column(String, nullable=False)  # Category name (linked to Category table)
    user_uid = Column(String(12), ForeignKey("users.user_uid"), nullable=False)  # FK to User table by UID
    username = Column(String, ForeignKey("users.username"), nullable=False)  # FK to User table by username
    status = Column(String, default="active")  # Resource status (active/inactive)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))  # Resource creation timestamp
    resource_secret = Column(String(60), nullable=False)  

    # ORM relationship to User
    user = relationship("User", back_populates="resources", foreign_keys=[username])

# -----------------------------
# User Table
# -----------------------------
class User(Base):
    __tablename__ = "users"  # Table name in DB

    user_uid = Column(String(12), primary_key=True, unique=True, index=True, nullable=False)  # Unique ID for user
    username = Column(String, unique=True, index=True)  # Username (used in login)
    email = Column(String, unique=True, index=True)  # User email
    phone_number = Column(String, unique=True, index=True, nullable=True)  # Optional phone number
    password = Column(String)  # Hashed password
    role = Column(String, default="user")  # Role of user (user/manager)
    is_active = Column(Boolean, default=True)  # Active status toggle
    password_changed_by = Column(String, nullable=True)  # Audit info (manager/user)
    resource_registered_by = Column(String, nullable=True)  # Audit info (manager/user)
    resource_removed_by = Column(String, nullable=True)  # Audit info (manager/user)
    last_token_issued_at = Column(DateTime, default=datetime.now(timezone.utc))  # Session token timestamp
    created_at = Column(DateTime, default=datetime.now(timezone.utc))  # Account creation time
    last_reset_sent_at = Column(DateTime, nullable=True)  # Rate-limit control for reset link

    # ORM relationship to Resource
    resources = relationship("Resource", back_populates="user", foreign_keys=[Resource.username])

# -----------------------------
# Category Table
# -----------------------------
class Category(Base):
    __tablename__ = "categories"  # Table name in DB

    name = Column(String, primary_key=True, unique=True, nullable=False)  # Category name for resource classification
    prefix = Column(String(4), unique=True, nullable=False)  # 4-character prefix (used in resource ID)

# -----------------------------
# Resource Ownership Table
# -----------------------------
class ResourceOwnership(Base):
    __tablename__ = "resource_ownership"  # Table name in DB

    resource_id = Column(String(12), ForeignKey("resources.resource_id"), primary_key=True)  # FK to resource table
    current_owner = Column(String)  # Current username
    previous_owners = Column(String)  # Comma-separated list of previous owners
    category = Column(String)  # Redundant for easier filtering (normalized form could use FK)
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))  # Auto update timestamp

    # ORM relationship to Resource
    resource = relationship("Resource")  # Allows `.resource` access from ownership record
