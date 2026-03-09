# Import necessary FastAPI, SQLAlchemy, and datetime utilities
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta, timezone

# Import internal models, schemas, and utility functions
from app import models, schemas
from app.limiter_config import limiter
from app.utils import(
    is_password_leaked, hash_passwd, verify_passwd, generate_user_uid,
    create_access_token, create_rst_token, verify_rst_token,
    get_current_user, send_whatsapp_with_temp, kill_user_sessions, log_event    
)
from app.database import get_db
from app.schemas import strong_passwd_field

# Initialize FastAPI router for /user endpoints
router = APIRouter(prefix="/user", tags=["User"])

# -----------------------------
# Endpoint to create a new user
# -----------------------------
@router.post("/create-user", response_model=schemas.UserOut)
def create_user(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Normalize and extract username from email
    email = user.email.strip().lower()
    username = email.split("@")[0].strip().lower()

    # Check for existing email account
    existing = db.query(models.User).filter((models.User.email == email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Account Creation Failed")

    if is_password_leaked(user.password):
        raise HTTPException(
            status_code=400,
            detail="This password has been found in known data breaches. Please use a more secure one."
        )
    
    if not strong_passwd_field(user.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be strong (uppercase, lowercase, number, special char)."
        )
    
    # Hash password and create new user object
    hashed_pw = hash_passwd(user.password)
    new_user = models.User(
        user_uid=generate_user_uid(db),
        username=username,
        email=email,
        phone_number=user.phone_number,
        password=hashed_pw,
        role="user"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log account creation
    log_event("info", "USER REGISTERED", f"{new_user.username} ({new_user.email})", request)
    return new_user

# -----------------------------
# Endpoint for user login
# -----------------------------
@router.post("/login")
@limiter.limit("5/minute")
def login_user(request: Request, data: schemas.Login, db: Session = Depends(get_db)):
    identifier = data.username_or_email

    # Find user by username or email
    user = db.query(models.User).filter(
        (models.User.username == identifier) | (models.User.email == identifier)
    ).first()

    # Validate credentials
    if not user or not verify_passwd(data.password, user.password):
        log_event("warning", "USER LOGIN", f"Failed login for {identifier}", request)
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    
    # Check if user is active
    if not user.is_active:
        log_event("warning", "USER LOGIN", f"Login attempt for deactivated account: {user.username}", request)
        raise HTTPException(status_code=403, detail="Account is deactivated")
    
    # Terminate previous sessions
    kill_user_sessions(db, user)
    
    # Create new JWT access token
    token = create_access_token({"sub": user.user_uid, "role": user.role}, user)

    # Log login event
    log_event("info", "USER LOGIN", f"Login successful for {user.username}", request)

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "uid": user.user_uid,
        "username": user.username,
        "email": user.email,
        "role": user.role
    }

# -----------------------------
# Get currently authenticated user details
# -----------------------------
@router.get("/user_details", response_model=schemas.UserOut)
def get_user(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Fetch user by UID from token
    user = db.query(models.User).filter_by(user_uid=current_user.user_uid).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Credentials or User")
    
    # Log profile fetch event
    log_event("info", "USER PROFILE", f"Fetched user profile: {current_user.username}", request)
    return user

# -----------------------------
# Send password reset link via WhatsApp
# -----------------------------
@router.post("/forgot-password")
@limiter.limit("3/minute")
def forgot_password(request: Request, data: schemas.ForgetPasswdReq, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Find user by phone number
    user = db.query(models.User).filter((models.User.phone_number == data.phone)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Credentials or User")
    
    # Check if reset was recently requested (rate limiting)
    if user.last_reset_sent_at and datetime.now(timezone.utc) - user.last_reset_sent_at < timedelta(minutes=10):
        raise HTTPException(status_code=429, detail="Try again later.")
    
    # Update timestamp and generate reset token
    user.last_reset_sent_at = datetime.now(timezone.utc)
    db.commit()
    
    token = create_rst_token(user.email)
    reset_link = f"http://127.0.0.1:8000/user/reset-password/{token}"

    # Attempt to send WhatsApp reset message
    try:
        send_whatsapp_with_temp(user.phone_number, reset_link)
        log_event("info", "PASSWORD RESET", f"Reset link sent to {user.phone_number}", request)
        return {"message": f"Reset Link sent to {data.phone}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send link: {e}")    

# -----------------------------
# Reset password using reset token
# -----------------------------
@router.post("/reset-password/{token}")
@limiter.limit("3/minute")
def reset_password(request: Request, token: str, new_password_data: schemas.ResetPasswdReq, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Decode token and get email
    email = verify_rst_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Look up user by email, username, or phone
    user = db.query(models.User).filter(
        (models.User.username == email) | (models.User.email == email) | (models.User.phone_number == email)
    ).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Credentials or User")

    if is_password_leaked(new_password_data.new_password):
        raise HTTPException(
            status_code=400,
            detail="This password has been found in known data breaches. Please use a more secure one."
        )
    
    if len(new_password_data.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long")

    if not strong_passwd_field(new_password_data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be strong (uppercase, lowercase, number, special char)."
        )

    # Hash and update password
    user.password = hash_passwd(new_password_data.new_password)
    user.password_changed_by = "Password reset by user"
    db.commit()
    db.refresh(user)

    # Invalidate old sessions
    kill_user_sessions(db, user)

    # Log password reset
    log_event("info", "PASSWORD RESET", f"Password reset for {user.username}", request)
    
    return {"message": "Password reset successful"}

# -----------------------------
# Authenticated password change
# -----------------------------
@router.post("/reset-password-auth")
@limiter.limit("3/minute")
def reset_password_authenticated(request: Request, data: schemas.AuthenticatedResetPasswdReq, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Find user by email/username
    user = db.query(models.User).filter(
        (models.User.username == data.email) | (models.User.email == data.email)
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="Invalid Credentials")

    # Verify current password
    if not verify_passwd(data.current_password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect current password")

    if is_password_leaked(data.new_password):
        raise HTTPException(
            status_code=400,
            detail="This password has been found in known data breaches. Please use a more secure one."
        )
    
    if len(data.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long")

    if not strong_passwd_field(data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be strong (uppercase, lowercase, number, special char)."
        )

    # Hash and update new password
    user.password = hash_passwd(data.new_password)
    user.password_changed_by = "Password changed by user"
    db.commit()
    db.refresh(user)

    # Invalidate existing sessions
    kill_user_sessions(db, user)

    # Log password update
    log_event("info", "PASSWORD RESET", f"Password changed by {user.username}", request)
    
    return {"message": "Password updated successfully"}