from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ApiKeyCreate(BaseModel):
    name: str


class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    prefix: str
    created_at: datetime
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ApiKeyCreated(ApiKeyResponse):
    api_key: str


class ProjectCreate(BaseModel):
    name: str


class ProjectResponse(BaseModel):
    id: UUID
    name: str
    created_at: datetime

    class Config:
        from_attributes = True


class TargetCreate(BaseModel):
    name: str
    base_url: str
    allowlisted_hosts: List[str]
    auth_header: Optional[str] = None
    api_key: Optional[str] = None
    canary_domain: Optional[str] = None
    pii_regexes: List[str] = []
    authorization_text: Optional[str] = None
    owner_attestation: bool = False


class TargetResponse(BaseModel):
    id: UUID
    name: str
    base_url: str
    allowlisted_hosts: List[str]
    auth_header: Optional[str]
    canary_domain: Optional[str]
    pii_regexes: List[str]

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    target_id: UUID
    openapi_url: Optional[str] = None
    openapi_file: Optional[str] = None
    postman_file: Optional[str] = None
    base_url: Optional[str] = None


class ScanResponse(BaseModel):
    id: UUID
    status: str
    created_at: datetime

    class Config:
        from_attributes = True
