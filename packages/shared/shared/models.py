from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Endpoint:
    method: str
    path: str
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    sample_body: Optional[Dict[str, Any]] = None


@dataclass
class AuthorizationRecord:
    confirmed: bool
    authorization_text: Optional[str]
    owner_attestation: bool


@dataclass
class TargetConfig:
    base_url: str
    allowlisted_hosts: List[str]
    auth_header: Optional[str] = None
    encrypted_api_key: Optional[str] = None
    canary_domain: Optional[str] = None
    pii_regexes: List[str] = field(default_factory=list)


@dataclass
class ScanContext:
    project_id: str
    target_id: str
    authorization: AuthorizationRecord
    endpoints: List[Endpoint]
    config: TargetConfig
