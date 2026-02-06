import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .db import Base


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="Viewer")
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    tenant = relationship("Tenant")


class Project(Base):
    __tablename__ = "projects"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    tenant = relationship("Tenant")


class Target(Base):
    __tablename__ = "targets"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    name = Column(String(200), nullable=False)
    base_url = Column(String(500), nullable=False)
    allowlisted_hosts = Column(JSON, nullable=False)
    auth_header = Column(String(100))
    encrypted_api_key = Column(Text)
    canary_domain = Column(String(255))
    pii_regexes = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    project = relationship("Project")


class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    confirmed = Column(Boolean, default=False)
    authorization_text = Column(Text)
    owner_attestation = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    target = relationship("Target")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    status = Column(String(50), default="queued")
    report_html = Column(Text)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    target = relationship("Target")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    action = Column(String(200), nullable=False)
    detail = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
