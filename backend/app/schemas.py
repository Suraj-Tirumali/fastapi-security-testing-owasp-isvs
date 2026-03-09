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
# Input model for device registration by admin
# -----------------------------
class DeviceCreate(BaseModel):
    email: EmailStr
    category: str

    @field_validator("category")
    @classmethod
    def lowercase_category(cls, v: str) -> str:
        return v.lower()


# -----------------------------
# Output model for device registration
# -----------------------------
class DeviceResponse(BaseModel):
    device_id: str
    category: str
    user_uid: str
    username: str
    status: str
# -----------------------------
# device login request
# -----------------------------
class DeviceLoginRequest(BaseModel):
    device_id: str


class DeviceLoginResponse(BaseModel):
    message: str
# -----------------------------
# Minimal device info
# -----------------------------
class DeviceInfo(BaseModel):
    device_id: str
    category: str

# -----------------------------
# Grouped count of devices by user
# -----------------------------
class UserDeviceList(BaseModel):
    category: str
    device_count: int
    devices: dict[str, int]

    class Config:
        from_attributes = True

# -----------------------------
# Output model: grouped users
# -----------------------------
class GroupedUserList(BaseModel):
    active_users: List[UserOut]
    inactive_users: List[UserOut]

# -----------------------------
# Output model: grouped user devices per category
# -----------------------------
class GroupedUserDevice(BaseModel):
    category: str
    device_count: int
    devices: Dict[str, int]  # username -> count

# -----------------------------
# Combined output for active/inactive grouped devices
# -----------------------------
class GroupedDeviceSummary(BaseModel):
    active_devices: List[GroupedUserDevice]
    inactive_devices: List[GroupedUserDevice]

    class Config:
        from_attributes = True

# -----------------------------
# Device model used in listing
# -----------------------------
class DeviceOut(BaseModel):
    device_id: str
    category: str
    user_uid: str
    username: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Simplified summary for a device
# -----------------------------
class DeviceSummary(BaseModel):
    device_id: str
    category: str
    status: str

# -----------------------------
# User + their devices model
# -----------------------------
class UserWithDevicesOut(BaseModel):
    user_uid: str
    username: str
    email: str
    phone: str
    devices: list[DeviceSummary] = []

# -----------------------------
# Admin password change request schema
# -----------------------------
class AdminPasswordChange(BaseModel):
    email: str
    new_password: str
    confirm_password: str

    @model_validator(mode="after")
    def check_passwords_match_and_strength(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match!")        
        return self
        
# -----------------------------
# Minimal device output for inactive state (no user info)
# -----------------------------
class InactiveDeviceOut1(BaseModel):
    device_id: str
    category: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Inactive device with ownership context
# -----------------------------
class InactiveDeviceOut(BaseModel):
    device_id: str
    category: str
    username: str
    user_uid: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Input model for re-registration of pre-owned device
# -----------------------------
class PreOwnedDeviceRequest(BaseModel):
    device_id: str
    category: str
    username: str

# -----------------------------
# Output model after claiming a pre-owned device
# -----------------------------
class PreOwnedDeviceResponse(BaseModel):
    device_id: str
    category: str
    username: str
    user_uid: str
    status: str

    class Config:
        from_attributes = True

# -----------------------------
# Ownership history output schema
# -----------------------------
class DeviceOwnershipOut(BaseModel):
    device_id: str
    category: str
    previous_owners: List[str]
    current_owner: str

    class Config:
        from_attributes = True