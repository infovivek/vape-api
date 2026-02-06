import pathlib
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from packages.shared.shared import AuthorizationRecord, ScanContext, TargetConfig
from packages.shared.shared.parsers import parse_openapi
from packages.shared.shared.scanner import Scanner


BASE_DIR = pathlib.Path(__file__).resolve().parents[1]


def main():
    openapi_path = BASE_DIR / "samples" / "sample_openapi.yaml"
    content = openapi_path.read_text()
    endpoints = parse_openapi(content)
    context = ScanContext(
        project_id="demo",
        target_id="demo-target",
        authorization=AuthorizationRecord(confirmed=True, authorization_text="Demo authorization", owner_attestation=True),
        endpoints=endpoints,
        config=TargetConfig(
            base_url="https://api.example.com",
            allowlisted_hosts=["api.example.com"],
            auth_header=None,
            canary_domain=None,
            pii_regexes=[r"\\b\\d{3}-\\d{2}-\\d{4}\\b"],
        ),
    )
    scanner = Scanner(context)
    findings, metadata = scanner.run()
    env = Environment(
        loader=FileSystemLoader("apps/api/app/templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    html = template.render(
        target={"name": "Demo Target", "base_url": context.config.base_url, "allowlisted_hosts": context.config.allowlisted_hosts},
        scan={"status": "completed"},
        findings=findings,
        metadata=metadata,
        generated_at=datetime.utcnow(),
    )
    output = BASE_DIR / "demo-report.html"
    output.write_text(html)
    print(f"Report written to {output}")


if __name__ == "__main__":
    main()
