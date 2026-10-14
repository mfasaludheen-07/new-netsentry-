import ipaddress
from datetime import datetime, timezone
from app.extensions import db
from app.models import IOC
from app.utils import classify_ip_address, is_private_or_internal_ip
from app.services.audit_service import AuditService


class IOCService:
    VALID_TYPES = {'IP', 'DOMAIN', 'HOSTNAME', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256'}
    VALID_STATUSES = {'UNKNOWN', 'OBSERVED', 'SUSPICIOUS', 'CONFIRMED', 'BENIGN'}
    VALID_CONFIDENCES = {'LOW', 'MEDIUM', 'HIGH'}

    @staticmethod
    def classify_ip(ip_str: str) -> str:
        """Classifies IP address according to RFC standards."""
        info = classify_ip_address(ip_str)
        return info['description']

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Determines whether IP is private/internal RFC range."""
        return is_private_or_internal_ip(ip_str)

    @classmethod
    def observe_ioc(cls, value: str, ioc_type: str, timestamp=None, notes: str = None) -> int:
        """
        Safely records or updates an observed IOC without prejudging it as malicious.
        Default initial status is OBSERVED with LOW confidence.
        """
        value = (value or '').strip()
        if not value:
            return 0

        ioc_type = ioc_type.upper() if ioc_type else 'DOMAIN'
        if ioc_type not in cls.VALID_TYPES:
            ioc_type = 'DOMAIN'

        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        existing = IOC.query.filter_by(value=value).first()
        if existing:
            existing.last_seen = timestamp
            if notes and not existing.notes:
                existing.notes = notes
            db.session.commit()
            return existing.id

        # New IOC
        default_note = notes
        if not default_note:
            if ioc_type == 'IP':
                default_note = f"Observed in network stream. Classification: {cls.classify_ip(value)}"
            else:
                default_note = "Observed in network telemetry stream."

        new_ioc = IOC(
            value=value,
            type=ioc_type,
            confidence='LOW',
            status='OBSERVED',
            first_seen=timestamp,
            last_seen=timestamp,
            notes=default_note
        )
        db.session.add(new_ioc)
        db.session.commit()
        return new_ioc.id

    @classmethod
    def update_status(cls, ioc_id: int, status: str, confidence: str, notes: str = None, user_id=None) -> bool:
        """
        Updates triage status and confidence for an IOC with audit logging.
        """
        status = status.upper() if status else ''
        confidence = confidence.upper() if confidence else ''

        if status not in cls.VALID_STATUSES or confidence not in cls.VALID_CONFIDENCES:
            return False

        ioc = db.session.get(IOC, ioc_id)
        if not ioc:
            return False

        ioc.status = status
        ioc.confidence = confidence
        if notes:
            ioc.notes = notes
        db.session.commit()

        AuditService.log(
            action='IOC_UPDATE',
            user_id=user_id,
            entity_type='IOC',
            entity_id=str(ioc_id),
            details=f"Updated status to {status} with {confidence} confidence for IOC '{ioc.value}'"
        )
        return True
