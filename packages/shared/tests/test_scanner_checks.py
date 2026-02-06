from httpx import Response

from packages.shared.shared.models import AuthorizationRecord, ScanContext, TargetConfig
from packages.shared.shared.scanner import Scanner


def _make_scanner():
    context = ScanContext(
        project_id="p1",
        target_id="t1",
        authorization=AuthorizationRecord(confirmed=True, authorization_text="ok", owner_attestation=True),
        endpoints=[],
        config=TargetConfig(
            base_url="https://api.example.com",
            allowlisted_hosts=["api.example.com"],
            pii_regexes=[r"\\b\\d{3}-\\d{2}-\\d{4}\\b"],
        ),
    )
    return Scanner(context)


def test_rate_limit_header_finding():
    scanner = _make_scanner()
    response = Response(200, headers={})
    scanner._check_rate_limit_headers(response, "https://api.example.com/users")
    assert scanner.findings


def test_pii_detection():
    scanner = _make_scanner()
    response = Response(200, text="User SSN 123-45-6789")
    scanner._check_pii(response)
    assert any("sensitive" in f.title.lower() for f in scanner.findings)


def test_cors_misconfig_detection():
    scanner = _make_scanner()
    response = Response(200, headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
    scanner._check_cors(response)
    assert any("cors" in f.title.lower() for f in scanner.findings)
