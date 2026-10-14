import json
from datetime import datetime, timezone
from app.extensions import db
from app.models import Case, Report, Alert, Endpoint, IOC, NetworkEvent, AttackStage, CaseMitre, Evidence, Finding, AnalystNote, CaseAlert, CaseEvent, CaseIOC
from app.services.timeline_service import TimelineService
from app.services.audit_service import AuditService


class ReportService:
    @classmethod
    def compile_report_data(cls, case_id: str) -> dict:
        case = db.session.get(Case, case_id)
        if not case:
            raise ValueError(f"Investigation Case {case_id} not found.")

        # 1. Associated Alerts
        alerts = db.session.query(Alert).join(
            CaseAlert, Alert.id == CaseAlert.alert_id
        ).filter(CaseAlert.case_id == case_id).all()

        # 2. Associated Endpoints
        # Check endpoints via case events or alerts
        endpoints = Endpoint.query.filter(
            (Endpoint.hostname.in_([a.endpoint for a in alerts if a.endpoint])) |
            (Endpoint.ip_address.in_([a.source_ip for a in alerts if a.source_ip]))
        ).all()

        # 3. Indicators of Compromise (IOCs)
        iocs = db.session.query(IOC).join(
            CaseIOC, IOC.id == CaseIOC.ioc_id
        ).filter(CaseIOC.case_id == case_id).all()

        # 4. Network Telemetry Events
        events = db.session.query(NetworkEvent).join(
            CaseEvent, NetworkEvent.id == CaseEvent.event_id
        ).filter(CaseEvent.case_id == case_id).order_by(NetworkEvent.timestamp.asc()).all()

        # 5. Timeline
        timeline = TimelineService.get_timeline(case_id)

        # 6. Attack Stages
        stages = AttackStage.query.filter_by(case_id=case_id).order_by(AttackStage.stage_order.asc()).all()

        # 7. MITRE Mappings
        mitre_mappings = CaseMitre.query.filter_by(case_id=case_id).all()

        # 8. Evidence Items
        evidence_items = Evidence.query.filter_by(case_id=case_id).order_by(Evidence.uploaded_at.asc()).all()

        # 9. Findings
        findings = Finding.query.filter_by(case_id=case_id).order_by(Finding.created_at.asc()).all()

        # 10. Notes
        notes = AnalystNote.query.filter_by(case_id=case_id).order_by(AnalystNote.created_at.asc()).all()

        return {
            'case': {
                'id': case.id,
                'title': case.title,
                'description': case.description,
                'severity': case.severity,
                'priority': case.priority,
                'status': case.status,
                'assigned_to': case.assignee.username if case.assignee else 'Unassigned',
                'created_by': case.creator.username if case.creator else 'System',
                'created_at': str(case.created_at),
                'updated_at': str(case.updated_at),
                'closed_at': str(case.closed_at) if case.closed_at else None
            },
            'alerts': [
                {
                    'id': a.id,
                    'rule_id': a.rule_id,
                    'title': a.title,
                    'severity': a.severity,
                    'source_ip': a.source_ip,
                    'destination_ip': a.destination_ip,
                    'endpoint': a.endpoint,
                    'event_count': a.event_count,
                    'first_seen': str(a.first_seen),
                    'last_seen': str(a.last_seen),
                    'confidence': a.confidence,
                    'status': a.status
                } for a in alerts
            ],
            'endpoints': [
                {
                    'id': ep.id,
                    'hostname': ep.hostname,
                    'ip_address': ep.ip_address,
                    'os_info': ep.os_info,
                    'criticality': ep.criticality,
                    'owner_description': ep.owner_description,
                    'alert_count': ep.alert_count
                } for ep in endpoints
            ],
            'iocs': [
                {
                    'id': i.id,
                    'value': i.value,
                    'type': i.type,
                    'status': i.status,
                    'confidence': i.confidence,
                    'notes': i.notes,
                    'first_seen': str(i.first_seen),
                    'last_seen': str(i.last_seen)
                } for i in iocs
            ],
            'events_summary': {
                'total_events': len(events),
                'sample': [
                    {
                        'id': ev.id,
                        'timestamp': str(ev.timestamp),
                        'source_ip': ev.source_ip,
                        'destination_ip': ev.destination_ip,
                        'source_port': ev.source_port,
                        'destination_port': ev.destination_port,
                        'protocol': ev.protocol,
                        'event_type': ev.event_type,
                        'action': ev.action,
                        'bytes_sent': ev.bytes_sent,
                        'bytes_received': ev.bytes_received
                    } for ev in events[:50]
                ]
            },
            'timeline': [
                {
                    'time': str(t.event_time),
                    'event_type': t.event_type,
                    'severity': t.severity,
                    'description': t.description,
                    'source': t.source,
                    'destination': t.destination
                } for t in timeline
            ],
            'attack_stages': [
                {
                    'order': s.stage_order,
                    'name': s.stage_name,
                    'status': s.status,
                    'confidence': s.confidence,
                    'evidence_summary': s.evidence_summary,
                    'analyst_comment': s.analyst_comment
                } for s in stages
            ],
            'mitre': [
                {
                    'technique_id': m.technique_id,
                    'name': m.technique.name if m.technique else m.technique_id,
                    'tactic': m.technique.tactic if m.technique else 'General',
                    'status': m.status,
                    'notes': m.notes
                } for m in mitre_mappings
            ],
            'evidence': [
                {
                    'id': e.id,
                    'filename': e.original_filename,
                    'mime_type': e.mime_type,
                    'size': e.size,
                    'hash_sha256': e.hash_sha256,
                    'uploaded_at': str(e.uploaded_at),
                    'description': e.description
                } for e in evidence_items
            ],
            'findings': [
                {
                    'id': f.id,
                    'title': f.title,
                    'description': f.description,
                    'confidence': f.confidence,
                    'status': f.status,
                    'created_at': str(f.created_at)
                } for f in findings
            ],
            'notes': [
                {
                    'id': n.id,
                    'author': n.author.username if n.author else 'Analyst',
                    'note': n.note,
                    'created_at': str(n.created_at)
                } for n in notes
            ],
            'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        }

    @classmethod
    def save_report(cls, case_id: str, title: str, summary: str = None, user_id: int = 1) -> int:
        data = cls.compile_report_data(case_id)
        report = Report(
            case_id=case_id,
            title=title,
            summary=summary or f"Forensic Investigation Report for Case {case_id}",
            report_data=json.dumps(data, indent=2),
            generated_by=user_id,
            generated_at=datetime.now(timezone.utc)
        )
        db.session.add(report)
        db.session.commit()

        AuditService.log(
            action='REPORT_GENERATE',
            user_id=user_id,
            entity_type='REPORT',
            entity_id=str(report.id),
            details=f"Generated formal forensic investigation report for case {case_id}"
        )
        return report.id
