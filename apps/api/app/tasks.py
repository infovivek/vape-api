from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List
import ipaddress
import socket

import httpx
from celery import Celery
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from .crypto import decrypt_value
from .db import SessionLocal
from .models import AuthorizationRecord, Scan, Target
from .settings import settings
from packages.shared.shared import AuthorizationRecord as AuthRecord
from packages.shared.shared import Endpoint, ScanContext, Scanner, TargetConfig, parse_openapi, parse_postman_collection

celery_app = Celery(
    "vapt_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

env = Environment(
    loader=FileSystemLoader("apps/api/app/templates"),
    autoescape=select_autoescape(["html"]),
)

PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
]


@celery_app.task(name="run_scan")
def run_scan(payload: Dict[str, Any]) -> None:
    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == payload["scan_id"]).first()
        target = db.query(Target).filter(Target.id == payload["target_id"]).first()
        auth_record = db.query(AuthorizationRecord).filter(AuthorizationRecord.target_id == target.id).first()
        if not scan or not target or not auth_record:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()
        try:
            endpoints = _build_endpoints(payload, target)
        except Exception as exc:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            scan.report_html = f\"<p>Scan failed: {exc}</p>\"
            db.commit()
            return
        api_key = decrypt_value(target.encrypted_api_key) if target.encrypted_api_key else None
        context = ScanContext(
            project_id=str(target.project_id),
            target_id=str(target.id),
            authorization=AuthRecord(
                confirmed=auth_record.confirmed,
                authorization_text=auth_record.authorization_text,
                owner_attestation=auth_record.owner_attestation,
            ),
            endpoints=endpoints,
            config=TargetConfig(
                base_url=target.base_url,
                allowlisted_hosts=target.allowlisted_hosts,
                auth_header=target.auth_header,
                encrypted_api_key=target.encrypted_api_key,
                canary_domain=target.canary_domain,
                pii_regexes=target.pii_regexes or [],
            ),
        )
        scanner = Scanner(context, api_key=api_key)
        findings, metadata = scanner.run()
        report_html = _render_report(target, scan, findings, metadata, auth_record)
        scan.report_html = report_html
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def _build_endpoints(payload: Dict[str, Any], target: Target) -> List:
    if payload.get("openapi_content"):
        return parse_openapi(payload["openapi_content"])
    if payload.get("postman_content"):
        return parse_postman_collection(payload["postman_content"])
    if payload.get("openapi_url"):
        if not _is_allowed_spec_url(payload["openapi_url"], target.allowlisted_hosts):
            raise ValueError("OpenAPI URL host not allowlisted")
        response = httpx.get(payload["openapi_url"], timeout=10.0)
        response.raise_for_status()
        return parse_openapi(response.text)
    return [Endpoint(method="GET", path="/", params={}, headers={}, sample_body=None)]


def _is_allowed_spec_url(url: str, allowlisted_hosts: List[str]) -> bool:
    host = httpx.URL(url).host or ""
    if host.lower() not in {h.lower() for h in allowlisted_hosts}:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            return not any(ip in net for net in PRIVATE_RANGES)
        except (socket.gaierror, ValueError):
            return False


def _render_report(target: Target, scan: Scan, findings, metadata: Dict[str, Any], auth_record: AuthorizationRecord) -> str:
    template = env.get_template("report.html")
    return template.render(
        target=target,
        scan=scan,
        authorization=auth_record,
        findings=findings,
        metadata=metadata,
        generated_at=datetime.utcnow(),
    )
