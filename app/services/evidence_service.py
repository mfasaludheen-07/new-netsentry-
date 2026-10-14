import os
import mimetypes
from datetime import datetime, timezone
from flask import current_app, request
from app.extensions import db
from app.models import Evidence, EvidenceChain
from app.utils import safe_storage_filename, compute_file_sha256
from app.services.audit_service import AuditService


class EvidenceService:
    ALLOWED_EXTENSIONS = {'csv', 'json', 'txt', 'log', 'pdf', 'png', 'jpg', 'jpeg', 'pcap', 'pcapng'}

    @classmethod
    def store_evidence(cls, case_id: str, uploaded_file, user_id: int, description: str = None) -> dict:
        result = {'success': False, 'message': '', 'evidence_id': None, 'sha256': None}

        if not uploaded_file or not uploaded_file.filename:
            result['message'] = "No valid file selected for upload."
            return result

        orig_filename = os.path.basename(uploaded_file.filename)
        ext = os.path.splitext(orig_filename)[1].lower().replace('.', '')

        if ext not in cls.ALLOWED_EXTENSIONS:
            result['message'] = f"Disallowed file type: .{ext}. Permitted formats: {', '.join(sorted(cls.ALLOWED_EXTENSIONS))}"
            return result

        storage_folder = current_app.config['EVIDENCE_FOLDER']
        os.makedirs(storage_folder, exist_ok=True)

        stored_filename = f"ev_{safe_storage_filename(orig_filename)}"
        dest_path = os.path.join(storage_folder, stored_filename)

        # Save to disk
        uploaded_file.save(dest_path)
        file_size = os.path.getsize(dest_path)

        # Validate max size
        max_size = current_app.config['MAX_CONTENT_LENGTH']
        if file_size > max_size:
            os.remove(dest_path)
            result['message'] = f"File exceeds maximum allowed size ({current_app.config['MAX_UPLOAD_MB']} MB)."
            return result

        # Calculate cryptographic SHA-256
        sha256_hash = compute_file_sha256(dest_path)

        mime_type = mimetypes.guess_type(orig_filename)[0] or 'application/octet-stream'

        evidence = Evidence(
            case_id=case_id,
            original_filename=orig_filename,
            stored_filename=stored_filename,
            mime_type=mime_type,
            size=file_size,
            hash_sha256=sha256_hash,
            description=description,
            uploaded_by=user_id,
            uploaded_at=datetime.now(timezone.utc)
        )
        db.session.add(evidence)
        db.session.commit()

        # Initial Chain of Custody record
        cls.log_chain(evidence.id, user_id, 'UPLOADED', current_hash=sha256_hash)

        AuditService.log(
            action='EVIDENCE_UPLOAD',
            user_id=user_id,
            entity_type='EVIDENCE',
            entity_id=str(evidence.id),
            details=f"Uploaded forensic evidence {orig_filename} (SHA-256: {sha256_hash}) for case {case_id}"
        )

        result['success'] = True
        result['message'] = "Forensic evidence secured and cryptographic SHA-256 integrity hash registered."
        result['evidence_id'] = evidence.id
        result['sha256'] = sha256_hash
        return result

    @staticmethod
    def log_chain(evidence_id: int, user_id: int, action: str, current_hash: str = None) -> bool:
        ip = '127.0.0.1'
        try:
            ip = request.remote_addr or '127.0.0.1'
        except RuntimeError:
            pass

        chain_record = EvidenceChain(
            evidence_id=evidence_id,
            user_id=user_id,
            action=action,
            action_timestamp=datetime.now(timezone.utc),
            ip_address=ip,
            current_hash=current_hash
        )
        db.session.add(chain_record)
        db.session.commit()
        return True

    @staticmethod
    def verify_integrity(evidence_id: int) -> dict:
        ev = db.session.get(Evidence, evidence_id)
        if not ev:
            return {'valid': False, 'message': 'Evidence record not found.'}

        dest_path = os.path.join(current_app.config['EVIDENCE_FOLDER'], ev.stored_filename)
        if not os.path.exists(dest_path):
            return {'valid': False, 'message': 'Physical file missing from storage repository.'}

        current_hash = compute_file_sha256(dest_path)
        is_intact = (current_hash.lower() == ev.hash_sha256.lower())

        return {
            'valid': is_intact,
            'expected_hash': ev.hash_sha256,
            'actual_hash': current_hash,
            'message': 'Cryptographic SHA-256 integrity verified successfully.' if is_intact else 'INTEGRITY MISMATCH DETECTED: File has been tampered with or corrupted!'
        }
