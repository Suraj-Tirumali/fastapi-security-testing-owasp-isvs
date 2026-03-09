# Import security, JWT, DB, and system tools
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta
from twilio.rest import Client
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import json
import os
import random
import logging
from pathlib import Path
from dotenv import load_dotenv

# Import internal models and database access
from app import models
from app.models import Category
from app.database import get_db

# -----------------------------
# Logger configuration
# -----------------------------
logger = logging.getLogger("app")
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Set up file logging
file_handler = logging.FileHandler("app.log")
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

# -----------------------------
# Password hashing context
# -----------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -------------------------------
# Loading environment varialbles
# -------------------------------
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# -----------------------------
# JWT configuration
# -----------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")
ALGORITHM = "HS256"
RESET_TOKEN_EXPIRE_MINUTES = 15

# -----------------------------
# FastAPI token auth scheme
# -----------------------------
token_auth_scheme = HTTPBearer()

# -----------------------------
# Digits for UID/device generation
# -----------------------------
DIGITS = "0123456789"

# ----------------------------------------------------
# Check whether the password exists in data breaches
# ----------------------------------------------------
ROCKYOU_PATH = os.getenv("ROCKYOU_PATH")
_leaked_passwords = set()

# -----------------------------
# Loads rockyou list
# -----------------------------
def load_rockyou_passwords():
    global _leaked_passwords
    if not _leaked_passwords:
        if not ROCKYOU_PATH:
            raise ValueError("ROCKYOU_PATH environment variable is not set.")
        if not os.path.exists(ROCKYOU_PATH):
            raise FileNotFoundError(f"rockyou.txt not found at: {ROCKYOU_PATH}")
        with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
            _leaked_passwords.update(p.strip() for p in f if p.strip())
    return _leaked_passwords

# -----------------------------------------------
# Checks if password exists in the rockyou list
# -----------------------------------------------
def is_password_leaked(password: str) -> bool:
    leaked = load_rockyou_passwords()
    return password in leaked

# -----------------------------
# Hash a plain password
# -----------------------------
def hash_passwd(password: str) -> str:
    return pwd_context.hash(password)

# -----------------------------
# Verify a hashed password
# -----------------------------
def verify_passwd(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# -----------------------------
# Get category prefix from DB or fallback to default
# -----------------------------
def get_category_prefix_from_db(category: str, db: Session) -> str:
    cat = db.query(Category).filter_by(name=category.lower()).first()
    if not cat:
        return "OT01"
    return cat.prefix

# -----------------------------
# Add new category into DB
# -----------------------------
def add_category_to_db(category: str, prefix: str, db: Session):
    if db.query(Category).filter_by(name=category.lower()).first():
        raise HTTPException(status_code=400, detail="Category Already Exists")
    new_cat = Category(name=category.lower(), prefix=prefix.upper())
    db.add(new_cat)
    db.commit()

# -----------------------------
# Generate unique 12-digit user UID
# -----------------------------
def generate_user_uid(db: Session, length: int = 12) -> str:
    while True:
        user_uid = ''.join(random.choices(DIGITS, k=length))
        exists = db.query(models.User).filter_by(user_uid=user_uid).first()
        if not exists:
            return user_uid

# -----------------------------
# Generate numeric UID (random)
# -----------------------------
def generate_numeric_uid(length: int = 12) -> str:
    return ''.join(random.choices(DIGITS, k=length))

# -----------------------------
# Generate device ID: prefix + 4-digit random + last 4 of user UID
# -----------------------------
def generate_device_id(prefix: str, user_uid: str) -> str:
    random_mid = ''.join(random.choices(DIGITS, k=4))
    suffix = user_uid[-4:]
    return prefix + random_mid + suffix

# -----------------------------
# Create a short-lived reset token for email
# -----------------------------
def create_rst_token(email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

# -----------------------------
# Verify reset token validity
# -----------------------------
def verify_rst_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

# -----------------------------
# Generate a 10-min JWT access token
# -----------------------------
def create_access_token(data: dict, user: models.User) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=10)
    to_encode = data.copy() | {"exp": expire, "iat": now.timestamp()}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -----------------------------
# Extract token string from Authorization header
# -----------------------------
def get_token(creds: HTTPAuthorizationCredentials = Depends(token_auth_scheme)) -> str:
    return creds.credentials

# -----------------------------
# Verify token and ensure role=admin
# -----------------------------
def verify_admin_token(creds: HTTPAuthorizationCredentials = Depends(token_auth_scheme)) -> dict:
    token = creds.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access restricted to admin only")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or Expired token")

# -----------------------------
# Validate token and return current user
# -----------------------------
def get_current_user(token: str = Depends(get_token), db: Session = Depends(get_db)) -> models.User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_uid = payload.get("sub")
        issued_at = payload.get("iat")
        role = payload.get("role")
        if not user_uid or not issued_at or role != "user":
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token error")

    # Fetch user from DB
    user = db.query(models.User).filter(models.User.user_uid == user_uid).first()
    if not user:
        raise HTTPException(status_code=403, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User access is revoked by admin")
    if user.last_token_issued_at.timestamp() > issued_at:
        raise HTTPException(status_code=403, detail="Session invalidated by admin")

    return user

# -----------------------------
# Check if current user has admin role
# -----------------------------
def get_current_admin_user(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    return user

# -----------------------------
# Send WhatsApp using Twilio with reset link
# -----------------------------
def send_whatsapp_with_temp(to_number: str, rst_link: str):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_whatsapp = os.getenv("TWILIO_WHATSAPP_FROM")
    template_sid = os.getenv("TWILIO_TEMPLATE_SID")

    client = Client(account_sid, auth_token)

    message = client.messages.create(
        from_=from_whatsapp,
        to=f"whatsapp:{to_number}",
        content_sid=template_sid,
        content_variables=json.dumps({
            "1": rst_link
        })
    )
    return message.sid

# -----------------------------
# Maintain ownership trail and update on registration
# -----------------------------
def update_device_ownership_on_registration(db: Session, device_id: str, new_owner: str, category: str):
    try:
        device_id = device_id.strip()
        ownership = db.query(models.DeviceOwnership).filter_by(device_id=device_id).first()

        if ownership:
            if ownership.current_owner.lower() != "unclaimed":
                prev = ownership.previous_owners
                ownership.previous_owners = prev if not prev else prev + ", " + ownership.current_owner
            ownership.current_owner = new_owner
            ownership.category = category
            db.commit()
        else:
            new_entry = models.DeviceOwnership(
                device_id=device_id,
                category=category,
                previous_owners="",
                current_owner=new_owner
            )
            db.add(new_entry)
            db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register ownership: {str(e)}")

# -----------------------------
# Mark a device as unclaimed and record previous owner
# -----------------------------
def mark_device_as_unclaimed(db: Session, device_id: str):
    ownership = db.query(models.DeviceOwnership).filter_by(device_id=device_id).first()

    if ownership:
        previous = ownership.previous_owners.split(",") if ownership.previous_owners else []
        current = ownership.current_owner.lower() if ownership.current_owner else ""
        if current and current != "unclaimed" and current not in [p.strip().lower() for p in previous]:
            previous.append(ownership.current_owner)
        ownership.previous_owners = ",".join(previous)
        ownership.current_owner = "unclaimed"
    
    # Log the ownership update
    log_event("info", "OWNERSHIP UPDATE", f"Device {device_id} marked as unclaimed")
    db.commit()

# -----------------------------
# Invalidate all active sessions of a user
# -----------------------------
def kill_user_sessions(db: Session, user: models.User):
    user.last_token_issued_at = datetime.now(timezone.utc)
    log_event("info", "SESSION KILL", f"Sessions invalidated for {user.username}")
    db.commit()

# -----------------------------
# Generic logger to log tagged events with IP and User-Agent
# -----------------------------
def log_event(level, tag, message, request=None):
    if request:
        try:
            client_ip = request.client.host
        except Exception:
            client_ip = "unknown"

        try:
            user_agent = request.headers.get("user-agent", "unknown")
        except Exception:
            user_agent = "unknown"
    else:
        client_ip = "?"
        user_agent = "?"

    log_msg = f"[{tag}] {message} | IP: {client_ip} | UA: {user_agent}"

    if level == "info":
        logger.info(log_msg)
    elif level == "warning":
        logger.warning(log_msg)
    elif level == "error":
        logger.error(log_msg)
    else:
        logger.debug(log_msg)