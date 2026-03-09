# Import required modules and types
from datetime import datetime
from typing import Dict, Optional, List
from pydantic import BaseModel, Field, EmailStr, model_validator, field_validator

# -----------------------------
# Password strength validator
# -----------------------------
def strong_passwd_field(pwd: str):
    return (
        any(c.isupper() for c in pwd) and
        any(c.islower() for c in pwd) and
        any(c.isdigit() for c in pwd) and
        any(not c.isalnum() for c in pwd)
    )

# -----------------------------
# User registration input model
# -----------------------------
class UserCreate(BaseModel):
    email: EmailStr
    phone_number: str
    password: str

# -----------------------------
# Login input model
# -----------------------------
class Login(BaseModel):
    username_or_email: str
    password: str

# -----------------------------
# Output model for user details
# -----------------------------
class UserOut(BaseModel):
    user_uid: str
    username: str
    email: EmailStr
    phone_number: Optional[str]
    role: str

    class Config:
        from_attributes = True  # Allows ORM conversion

# -----------------------------
# Input model for forgot password
# -----------------------------
class ForgetPasswdReq(BaseModel):
    phone: str

# -----------------------------
# Input model for reset password
# -----------------------------
class ResetPasswdReq(BaseModel):
    new_password: str
    confirm_password: str

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self

# -----------------------------
# Authenticated password reset model
# -----------------------------
class AuthenticatedResetPasswdReq(BaseModel):
    email: str
    current_password: str
    new_password: str
    confirm_password: str

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")  
        return self

# -----------------------------
# Input model for adding a category
# -----------------------------
class CategoryCreate(BaseModel):
    name: str
    prefix: str

# -----------------------------
# Output model for category info
# -----------------------------
class CategoryOut(BaseModel):
    name: str
    prefix: str

    class Config:
        from_attributes = True

# -----------------------------
# Input model for resource registration by manager
# -----------------------------
class ResourceCreate(BaseModel):
    email: EmailStr
    category: str

    @field_validator("category")
    @classmethod
    def lowercase_category(cls, v: str) -> str:
        return v.lower()


# -----------------------------
# Output model for resource registration
# -----------------------------
class ResourceResponse(BaseModel):
    resource_id: str
    category: str
    user_uid: str
    username: str
    status: str
# -----------------------------
# resource login request
# -----------------------------
class ResourceLoginRequest(BaseModel):
    resource_id: str


class ResourceLoginResponse(BaseModel):
    message: str
# -----------------------------
# Minimal resource info
# -----------------------------
class ResourceInfo(BaseModel):
    resource_id: str
    category: str

# -----------------------------
# Grouped count of resources by user
# -----------------------------
class UserResourceList(BaseModel):
    category: str
    resource_count: int
    resources: dict[str, int]

    class Config:
        from_attributes = True

# -----------------------------
# Output model: grouped users
# -----------------------------
class GroupedUserList(BaseModel):
    active_users: List[UserOut]
    inactive_users: List[UserOut]

# -----------------------------
# Output model: grouped user resources per category
# -----------------------------
class GroupedUserResource(BaseModel):
    category: str
    resource_count: int
    resources: Dict[str, int]  # username -> count

# -----------------------------
# Combined output for active/inactive grouped resources
# -----------------------------
class GroupedResourceSummary(BaseModel):
    active_resources: List[GroupedUserResource]
    inactive_resources: List[GroupedUserResource]

    class Config:
        from_attributes = True

# -----------------------------
# Resource model used in listing
# -----------------------------
class ResourceOut(BaseModel):
    resource_id: str
    category: str
    user_uid: str
    username: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Simplified summary for a resource
# -----------------------------
class ResourceSummary(BaseModel):
    resource_id: str
    category: str
    status: str

# -----------------------------
# User + their resources model
# -----------------------------
class UserWithResourcesOut(BaseModel):
    user_uid: str
    username: str
    email: str
    phone: str
    resources: list[ResourceSummary] = []

# -----------------------------
# Manager password change request schema
# -----------------------------
class ManagerPasswordChange(BaseModel):
    email: str
    new_password: str
    confirm_password: str

    @model_validator(mode="after")
    def check_passwords_match_and_strength(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match!")        
        return self
        
# -----------------------------
# Minimal resource output for inactive state (no user info)
# -----------------------------
class InactiveResourceOut1(BaseModel):
    resource_id: str
    category: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Inactive resource with ownership context
# -----------------------------
class InactiveResourceOut(BaseModel):
    resource_id: str
    category: str
    username: str
    user_uid: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Input model for re-registration of pre-owned resource
# -----------------------------
class PreOwnedResourceRequest(BaseModel):
    resource_id: str
    category: str
    username: str

# -----------------------------
# Output model after claiming a pre-owned resource
# -----------------------------
class PreOwnedResourceResponse(BaseModel):
    resource_id: str
    category: str
    username: str
    user_uid: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Ownership history output schema
# -----------------------------
class ResourceOwnershipOut(BaseModel):
    resource_id: str
    category: str
    previous_owners: List[str]
    current_owner: str

    class Config:
        from_attributes = True
