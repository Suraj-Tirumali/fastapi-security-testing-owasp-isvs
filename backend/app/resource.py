# Import FastAPI dependencies and database components
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List

# Import app modules
from app import models, schemas
from app.database import get_db
from app.utils import (
    hash_passwd, verify_passwd, get_current_user, generate_resource_id, get_category_prefix_from_db,
    update_resource_ownership_on_registration, mark_resource_as_unclaimed, log_event
)

# Create router instance for resource-related endpoints
router = APIRouter(prefix="/resources", tags=["Resources"])

# ------------------------------------------
# Get list of all available resource categories
# ------------------------------------------
@router.get("/available-categories", response_model=List[schemas.CategoryOut])
def list_available_categories(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    categories = db.query(models.Category).all()  # Fetch all category records
    # Log user's access to category list
    log_event("info", "CATEGORY LIST", f"User {current_user.username} viewed available categories", request)
    return categories

# ------------------------------------------
# Register a new resource for the current user
# ------------------------------------------
@router.post("/register-resource", response_model=schemas.ResourceResponse)
def register_resource(request: Request, resource: schemas.ResourceCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    prefix = get_category_prefix_from_db(resource.category.lower(), db)  # Get category prefix
    resource_id = generate_resource_id(prefix, current_user.user_uid)  # Generate full resource ID
    # for resource password
    raw_password = current_user.user_uid + resource_id
    hashed_password = hash_passwd(raw_password)

    # Create new resource entry
    new_resource = models.Resource(
        resource_id=resource_id,
        category=resource.category.lower(),
        user_uid=current_user.user_uid,
        username=current_user.username,
        status="active",
        resource_secret=hashed_password
    )
    
    # Update user record for audit
    current_user.resource_registered_by = f"Resource {resource_id} registered by user"
    db.add(new_resource)
    db.commit()
    db.refresh(new_resource)

    # Log ownership transfer
    update_resource_ownership_on_registration(
        db=db,
        resource_id=new_resource.resource_id,
        new_owner=current_user.username,
        category=resource.category
    )

    # Log resource registration
    log_event("info", "RESOURCE REGISTERED", f"Resource {resource_id} registered by {current_user.username}", request)

    return schemas.ResourceResponse(
        resource_id=resource_id,
        category=resource.category,
        user_uid=current_user.user_uid,
        username=current_user.username,
        status=new_resource.status
    )

# ------------------------------------------
# resource login for the current user
# ------------------------------------------
@router.post("/resource-login", response_model=schemas.ResourceLoginResponse)
def resource_login(data: schemas.ResourceLoginRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    resource = db.query(models.Resource).filter_by(resource_id=data.resource_id).first()
    
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Check if the resource belongs to the current user
    if resource.user_uid != current_user.user_uid:
        raise HTTPException(status_code=403, detail="Access denied: resource does not belong to current user")

    # Reconstruct password automatically: user_uid + resource_id
    raw_input_password = f"{resource.user_uid}{resource.resource_id}"

    # Compare with hashed resource password
    if not verify_passwd(raw_input_password, resource.resource_secret):
        raise HTTPException(status_code=401, detail="Invalid resource authentication")

    return {"message": f"Resource {data.resource_id} logged in successfully"}


# ------------------------------------------
# Get all active resources owned by the user
# ------------------------------------------
@router.get("/resource-details", response_model=List[schemas.ResourceOut])
def get_resource_details(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    resources = db.query(models.Resource).filter_by(
        username=current_user.username, status="active"
    ).all()  # Fetch active resources for user

    if not resources:
        raise HTTPException(status_code=404, detail="No resources found")

    # Log resource listing
    log_event("info", "RESOURCE LIST", f"{current_user.username} listed their active resources", request)
    return resources

# ------------------------------------------
# De-register a resource owned by the user
# ------------------------------------------
@router.post("/de-register-resource/{resource_id}")
def deregister_resource(request: Request, resource_id: str, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    resource = db.query(models.Resource).filter_by(resource_id=resource_id).first()  # Fetch resource by ID

    # Ensure resource exists and is owned by current user
    if not resource or resource.username != current_user.username:
        raise HTTPException(status_code=403, detail="You do not own this resource or it doesn't exist")
    
    # Mark resource as inactive
    resource.status = "inactive"
    current_user.resource_removed_by = f"Resource {resource_id} marked inactive by user"
    db.commit()

    # Update ownership record to unclaimed
    mark_resource_as_unclaimed(db, resource.resource_id)

    # Log resource deactivation
    log_event("info", "RESOURCE DEREGISTERED", f"{resource_id} marked inactive by {current_user.username}", request)
    return {"message": f"Resource {resource_id} has been De-Registered"}

# ------------------------------------------
# List all inactive resources in the system
# ------------------------------------------
@router.get("/list-inactive-resources", response_model=list[schemas.InactiveResourceOut1])
def list_inactive_resources(request: Request, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    resources = db.query(models.Resource).filter(models.Resource.status == "inactive").all()

    if not resources:
        raise HTTPException(status_code=404, detail="No inactive resources found")

    # Log action
    log_event("info", "RESOURCE LIST", f"{current_user.username} listed inactive resources", request)

    # Return filtered inactive resources
    return [
        schemas.InactiveResourceOut1(
            resource_id=d.resource_id,
            category=d.category,
            status=d.status
        )
        for d in resources
    ]

# ------------------------------------------
# Re-register an inactive (pre-owned) resource
# ------------------------------------------
@router.post("/re-register-resource", response_model=schemas.PreOwnedResourceResponse)
def re_register_pre_owned_resource(request: Request, resource: schemas.PreOwnedResourceRequest, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Verify that resource is inactive and exists
    existing_resource = db.query(models.Resource).filter(models.Resource.resource_id == resource.resource_id, models.Resource.status == "inactive").first()
    if not existing_resource:
        raise HTTPException(status_code=404, detail="This resource is owned by other user! You can only register inactive resources on your name.")

    # Modify resource ID's last 4 digits to match new owner's UID
    old_resource_id = existing_resource.resource_id
    updated_resource_id = old_resource_id[:-4] + current_user.user_uid[-4:]

    # Update ownership tracking
    update_resource_ownership_on_registration(
        db=db,
        resource_id=old_resource_id,
        new_owner=current_user.username,
        category=existing_resource.category
    )
    new_raw_password = current_user.user_uid + updated_resource_id
    existing_resource.resource_secret = hash_passwd(new_raw_password)
    
    # Update resource record with new owner
    existing_resource.resource_id = updated_resource_id
    existing_resource.user_uid = current_user.user_uid
    existing_resource.username = current_user.username
    existing_resource.status = "active"
    existing_resource.email = current_user.email

    db.commit()
    db.refresh(existing_resource)

    # Log re-registration
    log_event("info", "RESOURCE RE-REGISTERED", f"{updated_resource_id} claimed by {current_user.username}", request)
    
    return {
        "resource_id": existing_resource.resource_id,
        "user_uid": existing_resource.user_uid,
        "username": existing_resource.username,
        "category": existing_resource.category,
        "status": existing_resource.status
    }
