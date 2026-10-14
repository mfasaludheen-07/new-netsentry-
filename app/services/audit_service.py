from flask import request
from flask_login import current_user
from app.extensions import db
from app.models import AuditLog


class AuditService:
    @staticmethod
    def log(action: str, user_id=None, entity_type: str = None, entity_id: str = None, details: str = None) -> bool:
        """
        Records an immutable audit event in the system audit trail.
        """
        try:
            # Resolve user_id if not explicitly provided
            if user_id is None and current_user and current_user.is_authenticated:
                user_id = current_user.id

            ip_address = None
            user_agent = None

            try:
                ip_address = request.remote_addr or '127.0.0.1'
                user_agent = request.user_agent.string if request.user_agent else 'System/Internal'
                if user_agent and len(user_agent) > 250:
                    user_agent = user_agent[:250]
            except RuntimeError:
                # Outside HTTP request context (CLI, background worker)
                ip_address = '127.0.0.1'
                user_agent = 'CLI / Background Task'

            audit_entry = AuditLog(
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=str(entity_id) if entity_id is not None else None,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent
            )
            db.session.add(audit_entry)
            db.session.commit()
            return True
        except Exception as e:
            # Audit failures must not crash caller, but log error
            db.session.rollback()
            print(f"[AuditService Error] Failed to record audit log: {e}")
            return False
