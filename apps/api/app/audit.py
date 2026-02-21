from sqlalchemy.orm import Session

from .models import AuditLog


def log_action(db: Session, tenant_id, actor_id, action: str, detail: dict) -> None:
    entry = AuditLog(tenant_id=tenant_id, actor_id=actor_id, action=action, detail=detail)
    db.add(entry)
    db.commit()
