# Import FastAPI dependencies and database components
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

# Import app modules
from app import models, schemas
from app.database import get_db
from app.utils import (
    hash_passwd, verify_passwd, get_current_user, generate_device_id, get_category_prefix_from_db,
    update_device_ownership_on_registration, mark_device_as_unclaimed, log_event
)

# Create router instance for device-related endpoints
router = APIRouter(prefix="/device", tags=["Device"])

# ------------------------------------------
# Get list of all available device categories
# ------------------------------------------
@router.get("/available-categories", response_model=List[schemas.CategoryOut])
def list_available_categories(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    categories = db.query(models.Category).all()  # Fetch all category records
    # Log user's access to category list
    log_event("info", "CATEGORY LIST", f"User {models.User.username} viewed available categories", request)
    return categories

# ------------------------------------------
# Register a new device for the current user
# ------------------------------------------
@router.post("/register-device", response_model=schemas.DeviceResponse)
def register_device(request: Request, device: schemas.DeviceCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    prefix = get_category_prefix_from_db(device.category.lower(), db)  # Get category prefix
    device_id = generate_device_id(prefix, current_user.user_uid)  # Generate full device ID
    # for device password
    raw_password = current_user.user_uid + device_id
    hashed_password = hash_passwd(raw_password)

    # Create new device entry
    new_device = models.Device(
        device_id=device_id,
        category=device.category.lower(),
        user_uid=current_user.user_uid,
        username=current_user.username,
        status="active",
        device_password=hashed_password
    )
    
    # Update user record for audit
    current_user.device_registered_by = f"Device {device_id} registered by user"
    db.add(new_device)
    db.commit()
    db.refresh(new_device)

    # Log ownership transfer
    update_device_ownership_on_registration(
        db=db,
        device_id=new_device.device_id,
        new_owner=current_user.username,
        category=device.category
    )

    # Log device registration
    log_event("info", "DEVICE REGISTERED", f"Device {device_id} registered by {current_user.username}", request)

    return schemas.DeviceResponse(
        device_id=device_id,
        category=device.category,
        user_uid=current_user.user_uid,
        username=current_user.username,
        status=new_device.status
    )

# ------------------------------------------
# device login for the current user
# ------------------------------------------
@router.post("/device-login", response_model=schemas.DeviceLoginResponse)
def device_login(data: schemas.DeviceLoginRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    device = db.query(models.Device).filter_by(device_id=data.device_id).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Check if the device belongs to the current user
    if device.user_uid != current_user.user_uid:
        raise HTTPException(status_code=403, detail="Access denied: device does not belong to current user")

    # Reconstruct password automatically: user_uid + device_id
    raw_input_password = f"{device.user_uid}{device.device_id}"

    # Compare with hashed device password
    if not verify_passwd(raw_input_password, device.device_password):
        raise HTTPException(status_code=401, detail="Invalid device authentication")

    return {"message": f"Device {data.device_id} logged in successfully"}


# ------------------------------------------
# Get all active devices owned by the user
# ------------------------------------------
@router.get("/device-details", response_model=List[schemas.DeviceOut])
def get_device_details(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(models.Device).filter_by(
        username=current_user.username, status="active"
    ).all()  # Fetch active devices for user

    if not devices:
        raise HTTPException(status_code=404, detail="No devices found")

    # Log device listing
    log_event("info", "DEVICE LIST", f"{current_user.username} listed their active devices", request)
    return devices

# ------------------------------------------
# De-register a device owned by the user
# ------------------------------------------
@router.post("/de-register-device/{device_id}")
def deregister_device(request: Request, device_id = str, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    device = db.query(models.Device).filter_by(device_id=device_id).first()  # Fetch device by ID

    # Ensure device exists and is owned by current user
    if not device or device.username != current_user.username:
        raise HTTPException(status_code=403, detail="You do not own this device or it doesn't exist")
    
    # Mark device as inactive
    device.status = "inactive"
    current_user.device_deregistered_by = f"Device {device_id} marked inactive by user"
    db.commit()

    # Update ownership record to unclaimed
    mark_device_as_unclaimed(db, device.device_id)

    # Log device deactivation
    log_event("info", "DEVICE DEREGISTERED", f"{device_id} marked inactive by {current_user.username}", request)
    return {"message": f"Device {device_id} has been De-Registered"}

# ------------------------------------------
# List all inactive devices in the system
# ------------------------------------------
@router.get("/list-inactive-devices", response_model=list[schemas.InactiveDeviceOut1])
def list_inactive_devices(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(models.Device).filter(models.Device.status == "inactive").all()

    if not devices:
        raise HTTPException(status_code=404, detail="No inactive devices found")

    # Log action
    log_event("info", "DEVICE LIST", f"{current_user.username} listed inactive devices", request)

    # Return filtered inactive devices
    return [
        schemas.InactiveDeviceOut1(
            device_id=d.device_id,
            category=d.category,
            status=d.status
        )
        for d in devices
    ]

# ------------------------------------------
# Re-register an inactive (pre-owned) device
# ------------------------------------------
@router.post("/re-register-device", response_model=schemas.PreOwnedDeviceResponse)
def re_register_pre_owned_device(request: Request, device: schemas.PreOwnedDeviceRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Verify that device is inactive and exists
    existing_device = db.query(models.Device).filter(models.Device.device_id == device.device_id, models.Device.status == "inactive").first()
    if not existing_device:
        raise HTTPException(status_code=404, detail="This device is owned by other user! You can only register inactive devices on your name.")

    # Modify device ID's last 4 digits to match new owner's UID
    old_device_id = existing_device.device_id
    updated_device_id = old_device_id[:-4] + current_user.user_uid[-4:]

    # Update ownership tracking
    update_device_ownership_on_registration(
        db=db,
        device_id=old_device_id,
        new_owner=current_user.username,
        category=existing_device.category
    )
    new_raw_password = current_user.user_uid + updated_device_id
    existing_device.device_password = hash_passwd(new_raw_password)
    
    # Update device record with new owner
    existing_device.device_id = updated_device_id
    existing_device.user_uid = current_user.user_uid
    existing_device.username = current_user.username
    existing_device.status = "active"
    existing_device.email = current_user.email

    db.commit()
    db.refresh(existing_device)

    # Log re-registration
    log_event("info", "DEVICE RE-REGISTERED", f"{updated_device_id} claimed by {current_user.username}", request)
    
    return {
        "device_id": existing_device.device_id,
        "user_uid": existing_device.user_uid,
        "username": existing_device.username,
        "category": existing_device.category,
        "status": existing_device.status
    }