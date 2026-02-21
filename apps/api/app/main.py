from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import httpx
import pyotp
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .audit import log_action
from .auth import (
    create_access_token,
    generate_api_key,
    get_current_user,
    hash_api_key,
    hash_password,
    require_role,
    verify_password,
)
from .crypto import encrypt_value
from .db import get_db
from .models import ApiKey, AuthorizationRecord, Project, Scan, Target, Tenant, User
from .schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyResponse,
    ProjectCreate,
    ProjectResponse,
    ScanResponse,
    TargetCreate,
    TargetResponse,
    TokenResponse,
    UserCreate,
    UserLogin,
)
from .settings import settings
from .tasks import run_scan

app = FastAPI(title="Authorized API VAPT Scanner")

RETENTION_DAYS = 7

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/auth/register", response_model=TokenResponse)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    tenant = Tenant(name=payload.tenant_name)
    user = User(email=payload.email, password_hash=hash_password(payload.password), role="TenantAdmin", tenant=tenant)
    db.add(tenant)
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(str(user.id))
    log_action(db, tenant.id, user.id, "register", {"email": payload.email})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.mfa_enabled:
        if not payload.totp_code or not pyotp.TOTP(user.mfa_secret).verify(payload.totp_code):
            raise HTTPException(status_code=401, detail="Invalid TOTP")
    token = create_access_token(str(user.id))
    log_action(db, user.tenant_id, user.id, "login", {})
    return TokenResponse(access_token=token)


@app.post("/auth/api-keys", response_model=ApiKeyCreated)
def create_api_key(
    payload: ApiKeyCreate,
    user: User = Depends(require_role("TenantAdmin", "Analyst", "SuperAdmin")),
    db: Session = Depends(get_db),
):
    if not settings.api_key_salt:
        raise HTTPException(status_code=500, detail="API key salt not configured")
    raw_key = generate_api_key()
    api_key = ApiKey(
        tenant_id=user.tenant_id,
        user_id=user.id,
        name=payload.name,
        prefix=raw_key[:8],
        hashed_key=hash_api_key(raw_key),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    log_action(db, user.tenant_id, user.id, "api_key_created", {"api_key_id": str(api_key.id)})
    return ApiKeyCreated(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        api_key=raw_key,
    )


@app.get("/auth/api-keys", response_model=list[ApiKeyResponse])
def list_api_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ApiKey).filter(ApiKey.user_id == user.id).all()


@app.delete("/auth/api-keys/{api_key_id}")
def revoke_api_key(
    api_key_id: UUID,
    user: User = Depends(require_role("TenantAdmin", "Analyst", "SuperAdmin")),
    db: Session = Depends(get_db),
):
    api_key = db.query(ApiKey).filter(ApiKey.id == api_key_id, ApiKey.user_id == user.id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    db.delete(api_key)
    db.commit()
    log_action(db, user.tenant_id, user.id, "api_key_revoked", {"api_key_id": str(api_key_id)})
    return {"status": "revoked"}

@app.post("/auth/mfa/setup")
def setup_mfa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    user.mfa_enabled = True
    db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Authorized VAPT")
    log_action(db, user.tenant_id, user.id, "mfa_enabled", {})
    return {"secret": secret, "uri": uri}


@app.post("/projects", response_model=ProjectResponse)
def create_project(payload: ProjectCreate, user: User = Depends(require_role("TenantAdmin", "SuperAdmin")), db: Session = Depends(get_db)):
    project = Project(name=payload.name, tenant_id=user.tenant_id)
    db.add(project)
    db.commit()
    db.refresh(project)
    log_action(db, user.tenant_id, user.id, "project_created", {"project_id": str(project.id)})
    return project


@app.get("/projects", response_model=list[ProjectResponse])
def list_projects(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Project).filter(Project.tenant_id == user.tenant_id).all()


@app.post("/targets", response_model=TargetResponse)
def create_target(payload: TargetCreate, user: User = Depends(require_role("TenantAdmin", "Analyst", "SuperAdmin")), db: Session = Depends(get_db)):
    if not payload.authorization_text and not payload.owner_attestation:
        raise HTTPException(status_code=400, detail="Authorization required")
    if not payload.allowlisted_hosts:
        raise HTTPException(status_code=400, detail="Allowlisted hosts required")
    base_host = httpx.URL(payload.base_url).host if payload.base_url else None
    if base_host and base_host not in payload.allowlisted_hosts:
        raise HTTPException(status_code=400, detail="Base URL host must be allowlisted")
    encrypted_api_key = encrypt_value(payload.api_key) if payload.api_key else None
    target = Target(
        project_id=_default_project_id(db, user),
        name=payload.name,
        base_url=payload.base_url,
        allowlisted_hosts=payload.allowlisted_hosts,
        auth_header=payload.auth_header,
        encrypted_api_key=encrypted_api_key,
        canary_domain=payload.canary_domain,
        pii_regexes=payload.pii_regexes,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    auth_record = AuthorizationRecord(
        target_id=target.id,
        confirmed=True,
        authorization_text=payload.authorization_text,
        owner_attestation=payload.owner_attestation,
    )
    db.add(auth_record)
    db.commit()
    log_action(db, user.tenant_id, user.id, "target_created", {"target_id": str(target.id)})
    return target


@app.get("/targets", response_model=list[TargetResponse])
def list_targets(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(Target)
        .join(Project, Target.project_id == Project.id)
        .filter(Project.tenant_id == user.tenant_id)
        .all()
    )


@app.post("/scans", response_model=ScanResponse)
async def create_scan(
    target_id: UUID = Form(...),
    base_url: Optional[str] = Form(None),
    openapi_url: Optional[str] = Form(None),
    openapi_file: Optional[UploadFile] = File(None),
    postman_file: Optional[UploadFile] = File(None),
    user: User = Depends(require_role("TenantAdmin", "Analyst", "SuperAdmin")),
    db: Session = Depends(get_db),
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    auth_record = db.query(AuthorizationRecord).filter(AuthorizationRecord.target_id == target_id).first()
    if not auth_record or not auth_record.confirmed:
        raise HTTPException(status_code=400, detail="Authorization record missing")
    scan = Scan(target_id=target_id, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    payload = {
        "scan_id": str(scan.id),
        "target_id": str(target.id),
        "base_url": base_url,
        "openapi_url": openapi_url,
    }
    if openapi_file:
        payload["openapi_content"] = (await openapi_file.read()).decode()
    if postman_file:
        payload["postman_content"] = (await postman_file.read()).decode()
    run_scan.delay(payload)
    log_action(db, user.tenant_id, user.id, "scan_started", {"scan_id": str(scan.id)})
    return scan


@app.get("/scans", response_model=list[ScanResponse])
def list_scans(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    return (
        db.query(Scan)
        .join(Target, Scan.target_id == Target.id)
        .join(Project, Target.project_id == Project.id)
        .filter(Project.tenant_id == user.tenant_id, Scan.created_at >= cutoff)
        .all()
    )


@app.get("/scans/{scan_id}/report")
def download_report(scan_id: UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or not scan.report_html:
        raise HTTPException(status_code=404, detail="Report not found")
    if scan.created_at and scan.created_at < datetime.utcnow() - timedelta(days=RETENTION_DAYS):
        raise HTTPException(status_code=410, detail="Report expired")
    return {"report_html": scan.report_html}


@app.post("/scans/{scan_id}/stop")
def stop_scan(scan_id: UUID, user: User = Depends(require_role("TenantAdmin", "Analyst", "SuperAdmin")), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "stopped"
    scan.completed_at = datetime.utcnow()
    db.commit()
    log_action(db, user.tenant_id, user.id, "scan_stopped", {"scan_id": str(scan.id)})
    return {"status": "stopped"}


def _default_project_id(db: Session, user: User) -> UUID:
    project = db.query(Project).filter(Project.tenant_id == user.tenant_id).first()
    if project:
        return project.id
    project = Project(name="Default Project", tenant_id=user.tenant_id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project.id
