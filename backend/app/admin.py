# Import necessary modules and functions from FastAPI, SQLAlchemy, typing, and internal project files
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from sqlalchemy.orm import Session
from typing import List
import os

# Import internal models, schemas, database utilities, and helper functions
from app import models, schemas
from app.limiter_config import limiter
from app.models import Resource
from app.database import get_db
from app.utils import(
    is_password_leaked, hash_passwd, verify_admin_token, verify_passwd,
    generate_device_id, get_category_prefix_from_db,
    update_device_ownership_on_registration, mark_device_as_unclaimed,
    create_access_token, kill_user_sessions, log_event
)
from app.schemas import strong_passwd_field

# Initialize API router for all /admin routes
router = APIRouter(prefix="/admin", tags=["Admin"])

# -------------------------------
# ADMIN ACCOUNT CREATION
# -------------------------------
# Create a new admin user (requires existing admin token and secret key)
@router.post("/create-admin", response_model=schemas.UserOut, dependencies=[Depends(verify_admin_token)])
def create_admin(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db), x_secret_key: str = Header(...)):
    # Check secret key for extra authorization
    if x_secret_key != os.getenv("ADMIN_SECRET_KEY"):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    # Normalize email and extract username
    email = user.email.strip().lower()
    username = email.split("@")[0].strip().lower()

    # Prevent duplicate admin creation
    existing = db.query(models.User).filter((models.User.email == email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Account Creation Failed")
    
    # Create new admin user with hashed password
    hashed_pw = hash_passwd(user.password)
    new_admin = models.User(
        user_uid=generate_device_id("AD", username),
        username=username,
        email=email,
        phone_number=user.phone_number,
        password=hashed_pw,
        role="admin"
    )

    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    
    # Log admin creation
    log_event("info", "ADMIN CREATED", f"{new_admin.username} ({new_admin.email})", request)
    return new_admin

# -------------------------------
# ADMIN LOGIN
# -------------------------------
# Login endpoint for admin with rate limiting
@router.post("/login-admin")
@limiter.limit("3/minute")
async def login_admin(request: Request, data: schemas.Login, db: Session = Depends(get_db)):
    identifier = data.username_or_email
    password = data.password

    # Search admin by username or email
    admin = db.query(models.User).filter(
        (models.User.username == identifier) |
        (models.User.email == identifier)
    ).first()

    # Validate credentials and admin role
    if not admin or not verify_passwd(password, admin.password):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Unauthorized Activity")
    
    # Kill any previous active sessions
    kill_user_sessions(db, admin)

    # Generate new token for the session
    token = create_access_token({
        "sub": admin.user_uid,
        "role": "admin"
    }, admin)

    # Log admin login event
    log_event("info", "ADMIN LOGIN", f"{admin.username} authenticated", request)

    return {
        "message": "Admin Login successful",
        "access_token": token,
        "token_type": "bearer",
        "user_uid": admin.user_uid,
        "username": admin.username,
        "email": admin.email,
        "role": "admin"
    }

# -------------------------------
# LIST USERS
# -------------------------------
# Get list of active and inactive users
@router.get("/users", response_model=schemas.GroupedUserList, dependencies=[Depends(verify_admin_token)])
def list_all_users(request: Request, db: Session = Depends(get_db), skip: int = Query(0, ge=0), limit: int = Query(10, le=100)):
    users = db.query(models.User).offset(skip).limit(limit).all()

    active_users = []
    inactive_users = []

    # Classify users based on their status
    for user in users:
        user_data = schemas.UserOut(
            user_uid=user.user_uid,
            username=user.username,
            email=user.email,
            phone_number=user.phone_number,
            role=user.role
        )
        if user.is_active:
            active_users.append(user_data)
        else:
            inactive_users.append(user_data)

    # Log the list operation
    log_event("info", "USER LIST", "Admin listed all users", request)

    return {
        "active_users": active_users,
        "inactive_users": inactive_users
    }

# -------------------------------
# LIST RESOURCES
# -------------------------------
# Get grouped list of resources (active/inactive) by category and user
@router.get("/resources", response_model=schemas.GroupedDeviceSummary, dependencies=[Depends(verify_admin_token)])
def list_all_devices(request: Request, db: Session = Depends(get_db), skip: int = Query(0, ge=0), limit: int = Query(10, le=100)):
    resources = db.query(models.Resource).join(models.User, models.Resource.user_uid == models.User.user_uid).offset(skip).limit(limit).all()

    active_devices = {}
    inactive_devices = {}

    # Group resources by category and user
    for resource in resources:
        category = resource.category.lower()
        username = resource.username.lower()
        status = resource.status.lower()

        result = active_devices if status == "active" else inactive_devices

        if category not in result:
            result[category] = {
                "category": category,
                "resources": {},
                "device_count": 0
            }
        if username not in result[category]["resources"]:
            result[category]["resources"][username] = 0
        result[category]["resources"][username] += 1
        result[category]["device_count"] += 1

    # Log operation
    log_event("info", "RESOURCE LIST", "Admin listed all resources", request)

    return schemas.GroupedDeviceSummary(
        active_devices=[schemas.GroupedUserDevice(**val) for val in active_devices.values()],
        inactive_devices=[schemas.GroupedUserDevice(**val) for val in inactive_devices.values()]
    )

# -------------------------------
# LIST USERS WITH RESOURCES
# -------------------------------
# Show all users with their resources
@router.get("/list-users-with-resources", response_model=list[schemas.UserWithDevicesOut], dependencies=[Depends(verify_admin_token)])
def list_users_with_devices(request: Request, db: Session = Depends(get_db), skip: int = Query(0, ge=0), limit: int = Query(10, le=100)):
    users = db.query(models.User).offset(skip).limit(limit).all()
    result = []

    # Fetch and map resources per user
    for user in users:
        resources = db.query(models.Resource).filter(models.Resource.user_uid == user.user_uid).all()
        device_list = [
            schemas.DeviceSummary(
                device_id=d.device_id,
                category=d.category,
                status=d.status
            ) for d in resources
        ]

        result.append(
            schemas.UserWithDevicesOut(
                user_uid=user.user_uid,
                username=user.username,
                email=user.email,
                phone=user.phone_number,
                resources=device_list
            )
        )
    
    # Log the list action
    log_event("info", "USER RESOURCE LIST", "Admin fetched all users with resources", request)
    return result

# -------------------------------
# CHANGE USER PASSWORD
# -------------------------------
# Admin resets user's password
@router.post("/change-password", dependencies=[Depends(verify_admin_token)])
def admin_change_password(request: Request, data: schemas.AdminPasswordChange, db: Session = Depends(get_db)):
    email = data.email
    new_password = data.new_password
    confirm_password = data.confirm_password

    # Validate input and update password
    if not (email and new_password):
        raise HTTPException(status_code=400, detail="Username and new password required")

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if is_password_leaked(new_password):
        raise HTTPException(
            status_code=400,
            detail="This password has been found in known data breaches. Please use a more secure one."
        )
    
    if len(data.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long")
    
    if not strong_passwd_field(new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be strong (uppercase, lowercase, number, special char)."
        )

    user.password = hash_passwd(new_password)
    user.password_changed_by = "Password changed by admin"
    db.commit()

    # Log password change
    log_event("info", "PASSWORD RESET", f"Admin changed password for {email}", request)
    return {"message": f"Password for user with {email} updated"}

# -------------------------------
# REGISTER RESOURCE FOR USER
# -------------------------------
# Admin registers a resource on behalf of a user
@router.post("/register-resource-for-user", dependencies=[Depends(verify_admin_token)])
def register_device_for_user(request: Request, resource: schemas.DeviceCreate, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == resource.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    category = resource.category.lower()
    prefix = get_category_prefix_from_db(category, db)
    device_id = generate_device_id(prefix, user.user_uid)

     # 🔐 Generate raw password
    raw_password = user.user_uid + device_id
    hashed_password = hash_passwd(raw_password)

    # Add resource to user
    new_device = models.Resource(
        device_id=device_id,
        category=category,
        user_uid=user.user_uid,
        username=user.username,
        status="active",
        device_password=hashed_password 
    )
    db.add(new_device)
    user.device_registered_by = f"Resource {device_id} registered by admin"
    db.commit()
    db.refresh(new_device)

    # Update ownership tracking
    update_device_ownership_on_registration(
        db=db,
        device_id=new_device.device_id,
        new_owner=user.username,
        category=new_device.category
    )

    # Log registration
    log_event("info", "RESOURCE REGISTERED", f"Resource {device_id} registered by admin for {user.email}", request)
    return {"message": f"Resource registered with ID: {device_id}"}

# -------------------------------
# CATEGORY MANAGEMENT
# -------------------------------
# Add new resource category
@router.post("/add-category", response_model=schemas.CategoryOut, dependencies=[Depends(verify_admin_token)])
def add_device_category(request: Request, data: schemas.CategoryCreate, db : Session = Depends(get_db)):
    cleaned_name = data.name.replace(" ", "").lower()
    cleaned_prefix = data.prefix.replace(" ", "").upper()

    # Validate prefix length
    if len(cleaned_prefix) != 4:
        raise HTTPException(status_code=400, detail="Prefix must be exactly 4 characters")

    # Check for duplicates
    existing = db.query(models.Category).filter_by(name=cleaned_name, prefix=cleaned_prefix).first()
    if existing:
        raise HTTPException(status_code=400, detail="Category already exists")

    new_category = models.Category(name=cleaned_name, prefix=cleaned_prefix)
    db.add(new_category)
    db.commit()
    db.refresh(new_category)

    # Log category addition
    log_event("info", "CATEGORY ADDED", f"{cleaned_name} -> {cleaned_prefix}", request)
    return new_category

# Get list of all categories
@router.get("/categories", response_model=List[schemas.CategoryOut], dependencies=[Depends(verify_admin_token)])
def list_categories(request: Request, db: Session = Depends(get_db)):
    log_event("info", "CATEGORY LIST", "Admin listed all categories", request)
    return db.query(models.Category).all()

# -------------------------------
# DEREGISTER RESOURCE
# -------------------------------
# Admin deactivates a resource
@router.post("/deregister-resource/{device_id}", dependencies=[Depends(verify_admin_token)])
def deregister_device_admin(request: Request, device_id: str, db: Session = Depends(get_db)):
    resource = db.query(models.Resource).filter_by(device_id=device_id).first()
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    resource.status = "inactive"

    # Update user log if available
    user = db.query(models.User).filter(models.User.user_uid == resource.user_uid).first()
    if user:
        user.device_deregistered_by = f"Resource {resource.device_id} marked inactive by admin"
        db.add(user)

    db.commit()
    mark_device_as_unclaimed(db, resource.device_id)
    # log de-registeration
    log_event("info", "RESOURCE DEREGISTERED", f"Resource {device_id} marked inactive by admin", request)
    return {"message": f"Resource {device_id} marked as inactive"}

# -------------------------------
# LIST INACTIVE RESOURCES
# -------------------------------
# Return list of all inactive resources
@router.get("/list-inactive-resources", response_model=list[schemas.InactiveDeviceOut], dependencies=[Depends(verify_admin_token)])
def list_inactive_devices(request: Request, db: Session = Depends(get_db), skip: int = Query(0, ge=0), limit: int = Query(10, le=100)):
    resources = db.query(models.Resource).filter(models.Resource.status == "inactive").offset(skip).limit(limit).all()

    if not resources:
        raise HTTPException(status_code=404, detail="No inactive resources found")
    #log inactive resources
    log_event("info", "RESOURCE LIST", "Admin listed inactive resources", request)
    return [
        schemas.InactiveDeviceOut(
            device_id=d.device_id,
            category=d.category,
            username=d.username,
            user_uid=d.user_uid,
            status=d.status
        )
        for d in resources
    ]

# -------------------------------
# RESOURCE OWNERSHIP LOGGING
# -------------------------------
# View all resource ownership history
@router.get("/resource-ownerships", response_model=List[schemas.DeviceOwnershipOut], dependencies=[Depends(verify_admin_token)])
def list_device_ownerships(request: Request, db: Session = Depends(get_db), skip: int = Query(0, ge=0), limit: int = Query(10, le=100)):
    records = db.query(models.DeviceOwnership).offset(skip).limit(limit).all()
    # log ownership list
    log_event("info", "OWNERSHIP LIST", "Admin fetched resource ownerships", request)
    return [
        schemas.DeviceOwnershipOut(
            device_id=r.device_id,
            category=r.category,
            previous_owners=r.previous_owners.split(",") if r.previous_owners else [],
            current_owner=r.current_owner
        ) for r in records
    ]

# -------------------------------
# USER DEACTIVATION
# -------------------------------
# Admin disables a user and all their resources
@router.post("/deactivate-user/{user_uid}", dependencies=[Depends(verify_admin_token)])
def deactivate_user(request: Request, user_uid: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(user_uid=user_uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = False
    kill_user_sessions(db, user)

    # Deactivate all user's active resources
    resources = db.query(Resource).filter_by(user_uid=user_uid, status="active").all()
    for resource in resources:
        resource.status = "inactive"
        mark_device_as_unclaimed(db, resource.device_id)
        resource.device_deregistered_by = f"Auto-inactive due to admin deactivation of user {user_uid}"
        db.add(resource)

    db.commit()

    # log user deactivation
    log_event("info", "USER DEACTIVATED", f"User {user.username} and their resources were deactivated", request)
    return {"message": f"User {user_uid} deactivated and resources marked as inactive"}