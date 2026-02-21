from __future__ import annotations

import hashlib
import ipaddress
import socket
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from .models import Endpoint, ScanContext

PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
]


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    owasp_mapping: str
    asvs_mapping: str
    iso_mapping: str
    evidence: Dict[str, Any]
    reproduction_steps: List[str]
    remediation: str


@dataclass
class RateLimitState:
    capacity: int = 10
    tokens: int = 10
    refill_rate_per_sec: float = 1.0
    last_refill: float = field(default_factory=time.time)

    def consume(self, tokens: int = 1) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        refill = int(elapsed * self.refill_rate_per_sec)
        if refill > 0:
            self.tokens = min(self.capacity, self.tokens + refill)
            self.last_refill = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class SafeHttpClient:
    def __init__(self, base_url: str, allowlisted_hosts: List[str], max_requests: int = 60):
        self.base_url = base_url.rstrip("/")
        self.allowlisted_hosts = {host.lower() for host in allowlisted_hosts}
        self.state = RateLimitState()
        self.latencies: List[float] = []
        self.stop_reason: Optional[str] = None
        self.max_requests = max_requests
        self.request_count = 0
        self._client = httpx.Client(timeout=10.0)

    def close(self) -> None:
        self._client.close()

    def _is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host.lower() not in self.allowlisted_hosts:
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

    def request(self, method: str, url: str, headers: Dict[str, str], json_body: Optional[Dict[str, Any]]) -> Optional[httpx.Response]:
        if self.stop_reason:
            return None
        if self.request_count >= self.max_requests:
            self.stop_reason = "Global request budget exceeded"
            return None
        if not self._is_allowed(url):
            self.stop_reason = "Host not allowlisted or blocked by SSRF protection"
            return None
        if not self.state.consume():
            time.sleep(1)
        start = time.time()
        try:
            response = self._client.request(method, url, headers=headers, json=json_body)
        except httpx.RequestError:
            self.stop_reason = "Network error during request"
            return None
        latency = time.time() - start
        self.latencies.append(latency)
        self.request_count += 1
        if response.status_code in {429, 503}:
            if len(self.latencies) > 3 and sum(1 for r in self.latencies[-3:] if r > 0) >= 2:
                self.stop_reason = "Rate-limit or service-unavailable spike detected"
            time.sleep(1)
        if len(self.latencies) >= 5:
            baseline = sum(self.latencies[:3]) / 3
            if latency > baseline * 3:
                self.stop_reason = "Latency spike detected"
        return response


class Scanner:
    def __init__(self, context: ScanContext, api_key: Optional[str] = None):
        self.context = context
        self.api_key = api_key
        self.findings: List[Finding] = []

    def run(self) -> Tuple[List[Finding], Dict[str, Any]]:
        client = SafeHttpClient(self.context.config.base_url, self.context.config.allowlisted_hosts)
        try:
            self._check_bfla()
            for endpoint in self.context.endpoints:
                if client.stop_reason:
                    break
                self._run_checks(client, endpoint)
        finally:
            client.close()
        return self.findings, {"stop_reason": client.stop_reason, "latencies": client.latencies}

    def _auth_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "Authorized-VAPT-Scanner"}
        if self.context.config.auth_header and self.api_key:
            headers[self.context.config.auth_header] = self.api_key
        return headers

    def _run_checks(self, client: SafeHttpClient, endpoint: Endpoint) -> None:
        url = urljoin(self.context.config.base_url + "/", endpoint.path.lstrip("/"))
        headers = self._auth_headers()
        response = client.request(endpoint.method, url, headers=headers, json_body=endpoint.sample_body)
        if response is None:
            return
        self._check_rate_limit_headers(response, url)
        self._check_pii(response)
        self._check_cors(response)
        self._check_input_validation(client, response, url, endpoint)
        self._check_bola(client, endpoint)
        self._check_ssrf(client, endpoint)
        self._check_jwt_issues()
        self._check_mass_assignment(client, url, endpoint)
        self._check_verb_tampering(client, url, endpoint)
        self._check_schema_fuzzing(client, url, endpoint)

    def _record_finding(
        self,
        title: str,
        severity: str,
        confidence: str,
        evidence: Dict[str, Any],
        remediation: str,
        owasp: str,
        asvs: str,
        iso: str,
    ) -> None:
        self.findings.append(
            Finding(
                title=title,
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                remediation=remediation,
                owasp_mapping=owasp,
                asvs_mapping=asvs,
                iso_mapping=iso,
                reproduction_steps=["Run the scanner against the endpoint within approved scope."],
            )
        )

    def _redact(self, text: str) -> str:
        if len(text) > 200:
            text = text[:200] + "..."
        return re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", text)

    def _hash_snippet(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def _check_rate_limit_headers(self, response: httpx.Response, url: str) -> None:
        headers = response.headers
        if "x-ratelimit-limit" not in headers and "ratelimit-limit" not in headers:
            self._record_finding(
                title="Missing rate-limit headers",
                severity="Low",
                confidence="Low",
                evidence={"url": url, "status": response.status_code},
                remediation="Expose standard rate-limit headers to communicate quotas to clients.",
                owasp="API4:2023 Unrestricted Resource Consumption",
                asvs="V2.4",
                iso="A.8.2",
            )

    def _check_pii(self, response: httpx.Response) -> None:
        patterns = [re.compile(p, re.IGNORECASE) for p in self.context.config.pii_regexes]
        if not patterns:
            patterns = [re.compile(r"\b\d{3}-\d{2}-\d{4}\b")]  # default SSN-like
        body_text = response.text
        for pattern in patterns:
            if pattern.search(body_text):
                snippet = self._redact(body_text)
                self._record_finding(
                    title="Potential sensitive data exposure",
                    severity="Medium",
                    confidence="Medium",
                    evidence={"snippet": snippet, "hash": self._hash_snippet(snippet)},
                    remediation="Review response payloads and avoid returning unnecessary PII.",
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    asvs="V7.2",
                    iso="A.8.2",
                )
                break

    def _check_cors(self, response: httpx.Response) -> None:
        origin = response.headers.get("access-control-allow-origin")
        credentials = response.headers.get("access-control-allow-credentials")
        if origin == "*" and credentials == "true":
            self._record_finding(
                title="CORS wildcard with credentials",
                severity="Medium",
                confidence="High",
                evidence={"origin": origin, "credentials": credentials},
                remediation="Avoid wildcard origins when credentials are enabled.",
                owasp="API8:2023 Security Misconfiguration",
                asvs="V14.4",
                iso="A.5.23",
            )

    def _check_input_validation(self, client: SafeHttpClient, response: httpx.Response, url: str, endpoint: Endpoint) -> None:
        payload = "' OR 1=1 --"
        resp = response
        if endpoint.method == "GET":
            probe = urljoin(self.context.config.base_url + "/", endpoint.path.lstrip("/"))
            probe_url = str(httpx.URL(probe).copy_add_param("q", payload))
            resp = client.request("GET", probe_url, headers=self._auth_headers(), json_body=None)
        if resp and ("sql" in resp.text.lower() or "syntax" in resp.text.lower()):
            snippet = self._redact(resp.text)
            self._record_finding(
                title="Possible SQL error disclosure",
                severity="Medium",
                confidence="Low",
                evidence={"snippet": snippet, "hash": self._hash_snippet(snippet)},
                remediation="Return generic error messages and validate inputs server-side.",
                owasp="API8:2023 Security Misconfiguration",
                asvs="V5.3",
                iso="A.5.23",
            )

    def _check_bfla(self) -> None:
        if self.api_key:
            return
        self._record_finding(
            title="BFLA manual verification needed",
            severity="Low",
            confidence="Low",
            evidence={"note": "Multiple roles or API keys not provided."},
            remediation="Provide multiple API keys/roles to validate function-level authorization.",
            owasp="API5:2023 Broken Function Level Authorization",
            asvs="V4.1",
            iso="A.8.2",
        )

    def _check_bola(self, client: SafeHttpClient, endpoint: Endpoint) -> None:
        if "{id}" not in endpoint.path and "id" not in {k.lower() for k in endpoint.params.keys()}:
            return
        if endpoint.method != "GET":
            return
        path_variant = endpoint.path.replace("{id}", "1")
        url_one = urljoin(self.context.config.base_url + "/", path_variant.lstrip("/"))
        url_two = urljoin(self.context.config.base_url + "/", endpoint.path.replace("{id}", "2").lstrip("/"))
        resp_one = client.request("GET", url_one, headers=self._auth_headers(), json_body=None)
        resp_two = client.request("GET", url_two, headers=self._auth_headers(), json_body=None)
        if resp_one and resp_two and resp_one.status_code == 200 and resp_two.status_code == 200:
            self._record_finding(
                title="Potential BOLA/IDOR exposure",
                severity="High",
                confidence="Low",
                evidence={"status_one": resp_one.status_code, "status_two": resp_two.status_code},
                remediation="Enforce object-level authorization checks on resource identifiers.",
                owasp="API1:2023 Broken Object Level Authorization",
                asvs="V4.1",
                iso="A.8.2",
            )

    def _check_ssrf(self, client: SafeHttpClient, endpoint: Endpoint) -> None:
        if not self.context.config.canary_domain or endpoint.method != "GET":
            return
        base_url = urljoin(self.context.config.base_url + "/", endpoint.path.lstrip("/"))
        probe_url = str(httpx.URL(base_url).copy_add_param("url", self.context.config.canary_domain))
        resp = client.request(
            "GET",
            probe_url,
            headers=self._auth_headers(),
            json_body=None,
        )
        if resp and self.context.config.canary_domain in resp.text:
            self._record_finding(
                title="Potential SSRF reflection",
                severity="Medium",
                confidence="Low",
                evidence={"canary": self.context.config.canary_domain},
                remediation="Validate and restrict outbound requests to approved domains.",
                owasp="API7:2023 Server Side Request Forgery",
                asvs="V5.11",
                iso="A.8.2",
            )

    def _check_jwt_issues(self) -> None:
        if not self.api_key or self.api_key.count(".") != 2:
            return
        parts = self.api_key.split(".")
        if len(parts) != 3:
            return
        if "exp" not in parts[1]:
            self._record_finding(
                title="JWT missing exp claim",
                severity="Low",
                confidence="Low",
                evidence={"note": "Token payload missing exp"},
                remediation="Ensure JWTs include exp and validate it server-side.",
                owasp="API2:2023 Broken Authentication",
                asvs="V2.1",
                iso="A.8.2",
            )

    def _check_mass_assignment(self, client: SafeHttpClient, url: str, endpoint: Endpoint) -> None:
        if endpoint.method not in {"POST", "PUT", "PATCH"}:
            return
        body = endpoint.sample_body or {}
        body.update({"isAdmin": True})
        response = client.request(endpoint.method, url, headers=self._auth_headers(), json_body=body)
        if response is None:
            return
        if response.status_code < 400:
            self._record_finding(
                title="Potential mass assignment",
                severity="Medium",
                confidence="Low",
                evidence={"status": response.status_code, "field": "isAdmin"},
                remediation="Use explicit allowlists for mutable fields.",
                owasp="API6:2023 Mass Assignment",
                asvs="V5.2",
                iso="A.8.2",
            )

    def _check_verb_tampering(self, client: SafeHttpClient, url: str, endpoint: Endpoint) -> None:
        alternate = "GET" if endpoint.method != "GET" else "POST"
        response = client.request(alternate, url, headers=self._auth_headers(), json_body=endpoint.sample_body)
        if response is None:
            return
        if response.status_code < 400 and endpoint.method != alternate:
            self._record_finding(
                title="Verb tampering allowed",
                severity="Low",
                confidence="Low",
                evidence={"method": alternate, "status": response.status_code},
                remediation="Restrict allowed HTTP methods per endpoint.",
                owasp="API8:2023 Security Misconfiguration",
                asvs="V4.2",
                iso="A.5.23",
            )

    def _check_schema_fuzzing(self, client: SafeHttpClient, url: str, endpoint: Endpoint) -> None:
        if endpoint.method not in {"POST", "PUT", "PATCH"}:
            return
        body = endpoint.sample_body or {}
        fuzzed = {"unexpected": 123, **body}
        response = client.request(endpoint.method, url, headers=self._auth_headers(), json_body=fuzzed)
        if response is None:
            return
        if response.status_code < 400:
            self._record_finding(
                title="Schema validation lenient",
                severity="Low",
                confidence="Low",
                evidence={"status": response.status_code},
                remediation="Enforce schema validation on request bodies.",
                owasp="API8:2023 Security Misconfiguration",
                asvs="V5.3",
                iso="A.8.2",
            )
