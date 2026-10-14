import os
import csv
import json
from app.extensions import db
from app.models import LogUpload, NetworkEvent, Endpoint, IOC
from app.services.normalizer import EventNormalizer
from app.services.ioc_service import IOCService
from app.services.audit_service import AuditService


class LogParser:
    @classmethod
    def parse_file(cls, upload_id: int, file_path: str, source_type: str = 'Generic Network Log', timezone_str: str = 'UTC') -> dict:
        stats = {
            'processed': 0,
            'imported': 0,
            'skipped': 0,
            'invalid': 0,
            'errors': []
        }

        upload = db.session.get(LogUpload, upload_id)
        if not upload:
            stats['errors'].append(f"Upload record {upload_id} not found.")
            return stats

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            stats['errors'].append(f"Physical file missing or unreadable: {os.path.basename(file_path)}")
            upload.status = 'FAILED'
            upload.parsing_errors = "; ".join(stats['errors'])
            db.session.commit()
            return stats

        upload.status = 'PROCESSING'
        db.session.commit()

        ext = os.path.splitext(file_path)[1].lower().replace('.', '')

        try:
            if ext == 'json':
                stats = cls._parse_json(upload, file_path, source_type, stats)
            else:
                # Delimited / CSV / LOG / TXT
                stats = cls._parse_csv(upload, file_path, source_type, stats)

            final_status = 'COMPLETED' if stats['imported'] > 0 or stats['invalid'] == 0 else 'FAILED'
            upload.status = final_status
            upload.total_rows = stats['processed']
            upload.imported_rows = stats['imported']
            upload.skipped_rows = stats['skipped']
            upload.error_count = stats['invalid']
            if stats['errors']:
                upload.parsing_errors = "; ".join(stats['errors'][:10])

            db.session.commit()

            AuditService.log(
                action='LOG_PARSE',
                user_id=upload.uploaded_by,
                entity_type='LOG_UPLOAD',
                entity_id=str(upload_id),
                details=f"Parsed telemetry: {stats['imported']} imported, {stats['skipped']} skipped, {stats['invalid']} invalid"
            )

        except Exception as e:
            db.session.rollback()
            upload.status = 'FAILED'
            upload.parsing_errors = str(e)
            db.session.commit()
            stats['errors'].append(f"Fatal parser error: {e}")

        return stats

    @classmethod
    def _parse_csv(cls, upload: LogUpload, file_path: str, source_type: str, stats: dict) -> dict:
        with open(file_path, mode='r', encoding='utf-8', errors='replace') as f:
            # Detect delimiter
            sample = f.read(4096)
            f.seek(0)
            delimiter = ','
            if sample.count('\t') > sample.count(','):
                delimiter = '\t'
            elif sample.count(';') > sample.count(','):
                delimiter = ';'

            reader = csv.reader(f, delimiter=delimiter)
            try:
                headers = next(reader)
            except StopIteration:
                stats['errors'].append("Uploaded CSV file is completely empty.")
                return stats

            clean_headers = [str(h).strip().lower().strip('"\'') for h in headers]

            batch = []
            for row in reader:
                stats['processed'] += 1
                if not row or all(c.strip() == '' for c in row):
                    stats['skipped'] += 1
                    continue

                if len(row) != len(clean_headers):
                    stats['invalid'] += 1
                    continue

                raw_dict = dict(zip(clean_headers, row))
                normalized = EventNormalizer.normalize(raw_dict, source_type=source_type)

                if not normalized:
                    stats['invalid'] += 1
                    continue

                event = NetworkEvent(
                    upload_id=upload.id,
                    timestamp=normalized['timestamp'],
                    source_ip=normalized['source_ip'],
                    destination_ip=normalized['destination_ip'],
                    source_port=normalized['source_port'],
                    destination_port=normalized['destination_port'],
                    protocol=normalized['protocol'],
                    hostname=normalized['hostname'],
                    username=normalized['username'],
                    domain=normalized['domain'],
                    bytes_sent=normalized['bytes_sent'],
                    bytes_received=normalized['bytes_received'],
                    dns_query=normalized['dns_query'],
                    event_type=normalized['event_type'],
                    action=normalized['action'],
                    source_type=normalized['source_type'],
                    raw_event=normalized['raw_event']
                )
                batch.append(event)
                stats['imported'] += 1

                # Auto-profile Endpoint if internal hostname
                if normalized.get('hostname'):
                    cls._sync_endpoint(normalized['hostname'], normalized['source_ip'], normalized['timestamp'])

                # Auto-register external IOCs (IP, domain)
                cls._extract_iocs(normalized)

                if len(batch) >= 200:
                    db.session.add_all(batch)
                    db.session.commit()
                    batch = []

            if batch:
                db.session.add_all(batch)
                db.session.commit()

        return stats

    @classmethod
    def _parse_json(cls, upload: LogUpload, file_path: str, source_type: str, stats: dict) -> dict:
        with open(file_path, mode='r', encoding='utf-8', errors='replace') as f:
            try:
                payload = json.load(f)
            except json.JSONDecodeError as err:
                stats['errors'].append(f"Malformed JSON: {err}")
                return stats

        events_list = payload if isinstance(payload, list) else [payload]
        batch = []

        for item in events_list:
            stats['processed'] += 1
            if not isinstance(item, dict):
                stats['invalid'] += 1
                continue

            normalized = EventNormalizer.normalize(item, source_type=source_type)
            if not normalized:
                stats['invalid'] += 1
                continue

            event = NetworkEvent(
                upload_id=upload.id,
                timestamp=normalized['timestamp'],
                source_ip=normalized['source_ip'],
                destination_ip=normalized['destination_ip'],
                source_port=normalized['source_port'],
                destination_port=normalized['destination_port'],
                protocol=normalized['protocol'],
                hostname=normalized['hostname'],
                username=normalized['username'],
                domain=normalized['domain'],
                bytes_sent=normalized['bytes_sent'],
                bytes_received=normalized['bytes_received'],
                dns_query=normalized['dns_query'],
                event_type=normalized['event_type'],
                action=normalized['action'],
                source_type=normalized['source_type'],
                raw_event=normalized['raw_event']
            )
            batch.append(event)
            stats['imported'] += 1

            if normalized.get('hostname'):
                cls._sync_endpoint(normalized['hostname'], normalized['source_ip'], normalized['timestamp'])

            cls._extract_iocs(normalized)

            if len(batch) >= 200:
                db.session.add_all(batch)
                db.session.commit()
                batch = []

        if batch:
            db.session.add_all(batch)
            db.session.commit()

        return stats

    @staticmethod
    def _sync_endpoint(hostname: str, ip: str, timestamp):
        hostname = hostname.strip()
        if not hostname:
            return
        ep = Endpoint.query.filter_by(hostname=hostname).first()
        if not ep:
            ep = Endpoint(
                hostname=hostname,
                ip_address=ip,
                os_info='Workstation / Server',
                criticality='HIGH' if 'SERVER' in hostname.upper() else 'MEDIUM',
                owner_description=f"Auto-profiled internal host ({hostname})",
                first_seen=timestamp,
                last_seen=timestamp
            )
            db.session.add(ep)
        else:
            ep.last_seen = timestamp
            if not ep.ip_address:
                ep.ip_address = ip

    @staticmethod
    def _extract_iocs(event: dict):
        dst_ip = event.get('destination_ip')
        if dst_ip and not IOCService.is_private_ip(dst_ip):
            IOCService.observe_ioc(dst_ip, 'IP', timestamp=event.get('timestamp'))

        domain = event.get('domain')
        if domain and '.' in domain and not domain.endswith('.local'):
            IOCService.observe_ioc(domain, 'DOMAIN', timestamp=event.get('timestamp'))
