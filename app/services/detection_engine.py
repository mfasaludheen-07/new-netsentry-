from datetime import datetime, timezone
from sqlalchemy import text, func
from app.extensions import db
from app.models import DetectionRule, Alert, AlertEvent, Endpoint, Setting
from app.utils import generate_next_alert_id, is_private_or_internal_ip
from app.services.audit_service import AuditService


class DetectionEngine:
    @classmethod
    def run(cls, upload_id: int = None) -> dict:
        """
        Executes all enabled defensive detection rules against normalized telemetry.
        Can run scoped to a specific upload_id or globally.
        """
        generated_alerts = []
        rules = DetectionRule.query.filter_by(enabled=True).order_by(DetectionRule.id.asc()).all()

        for rule in rules:
            rule_id = rule.id
            threshold = rule.threshold or 5
            window = rule.time_window_seconds or 300
            rule_type = rule.rule_type

            if rule_type == 'PORT_SCAN':
                new_alerts = cls._detect_port_scan(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'HOST_SWEEP':
                new_alerts = cls._detect_host_sweep(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'FAILED_CONNS':
                new_alerts = cls._detect_failed_connections(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'UNUSUAL_EXTERNAL':
                new_alerts = cls._detect_unusual_external(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'REMOTE_SERVICES':
                new_alerts = cls._detect_remote_services(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'LARGE_TRANSFER':
                new_alerts = cls._detect_large_transfer(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'DNS_BURST':
                new_alerts = cls._detect_dns_burst(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)
            elif rule_type == 'BEACON_PATTERN':
                new_alerts = cls._detect_beacon_pattern(rule, upload_id, threshold, window)
                generated_alerts.extend(new_alerts)

        # Rule 009: Multiple Detection Combination Escalation
        multi_alerts = cls._detect_multi_detections()
        generated_alerts.extend(multi_alerts)

        # Sync endpoint alert counts
        cls.sync_endpoint_alert_counts()

        return {
            'total_alerts_generated': len(generated_alerts),
            'alerts': generated_alerts
        }

    @classmethod
    def _is_sqlite(cls):
        try:
            return db.engine.dialect.name == 'sqlite'
        except Exception:
            try:
                return 'sqlite' in str(db.session.get_bind().dialect.name).lower()
            except Exception:
                return False

    # -------------------------------------------------------------------------
    # RULE-001: Port Scan
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_port_scan(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        if cls._is_sqlite():
            query = text(f"""
                SELECT source_ip, destination_ip, hostname,
                       COUNT(DISTINCT destination_port) as distinct_ports,
                       GROUP_CONCAT(DISTINCT destination_port) as ports_list,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       COUNT(*) as event_count,
                       GROUP_CONCAT(id) as event_ids
                FROM network_events
                WHERE destination_port IS NOT NULL
                {upload_clause}
                GROUP BY source_ip, destination_ip, hostname
                HAVING distinct_ports >= :threshold
                   AND ((julianday(last_seen) - julianday(first_seen)) * 86400) <= :window
            """)
        else:
            query = text(f"""
                SELECT source_ip, destination_ip, hostname,
                       COUNT(DISTINCT destination_port) as distinct_ports,
                       GROUP_CONCAT(DISTINCT destination_port ORDER BY destination_port ASC SEPARATOR ', ') as ports_list,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       COUNT(*) as event_count,
                       GROUP_CONCAT(id SEPARATOR ',') as event_ids
                FROM network_events
                WHERE destination_port IS NOT NULL
                {upload_clause}
                GROUP BY source_ip, destination_ip, hostname
                HAVING distinct_ports >= :threshold
                   AND TIMESTAMPDIFF(SECOND, first_seen, last_seen) <= :window
            """)

        results = db.session.execute(query, {'threshold': threshold, 'window': max(window, 1)}).mappings().all()
        for r in results:
            desc = f"Source IP {r['source_ip']} probed {r['distinct_ports']} distinct destination ports ({r['ports_list']}) on target {r['destination_ip']}."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"Potential Port Scan against {r['destination_ip'] or 'target host'}",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip=r['destination_ip'],
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['event_count']),
                confidence='HIGH',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-002: Host Sweep
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_host_sweep(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        if cls._is_sqlite():
            query = text(f"""
                SELECT source_ip, hostname,
                       COUNT(DISTINCT destination_ip) as target_count,
                       GROUP_CONCAT(DISTINCT destination_ip) as targets_list,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       COUNT(*) as event_count,
                       GROUP_CONCAT(id) as event_ids
                FROM network_events
                WHERE (destination_ip LIKE '10.%' OR destination_ip LIKE '192.168.%' OR destination_ip LIKE '172.1%')
                {upload_clause}
                GROUP BY source_ip, hostname
                HAVING target_count >= :threshold
                   AND ((julianday(last_seen) - julianday(first_seen)) * 86400) <= :window
            """)
        else:
            query = text(f"""
                SELECT source_ip, hostname,
                       COUNT(DISTINCT destination_ip) as target_count,
                       GROUP_CONCAT(DISTINCT destination_ip SEPARATOR ', ') as targets_list,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       COUNT(*) as event_count,
                       GROUP_CONCAT(id SEPARATOR ',') as event_ids
                FROM network_events
                WHERE (destination_ip LIKE '10.%' OR destination_ip LIKE '192.168.%' OR destination_ip LIKE '172.1%')
                {upload_clause}
                GROUP BY source_ip, hostname
                HAVING target_count >= :threshold
                   AND TIMESTAMPDIFF(SECOND, first_seen, last_seen) <= :window
            """)

        results = db.session.execute(query, {'threshold': threshold, 'window': max(window, 1)}).mappings().all()
        for r in results:
            desc = f"Source {r['source_ip']} contacted {r['target_count']} distinct internal subnet hosts ({r['targets_list']})."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"Potential Internal Host Sweep by {r['hostname'] or r['source_ip']}",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip='Internal Subnet',
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['event_count']),
                confidence='HIGH',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-003: Repeated Failed Connections
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_failed_connections(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        concat_sql = "GROUP_CONCAT(id) as event_ids" if cls._is_sqlite() else "GROUP_CONCAT(id SEPARATOR ',') as event_ids"
        query = text(f"""
            SELECT source_ip, destination_ip, hostname,
                   COUNT(*) as failed_count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   {concat_sql}
            FROM network_events
            WHERE action IN ('DENY', 'BLOCK', 'DROP', 'REJECT')
            {upload_clause}
            GROUP BY source_ip, destination_ip, hostname
            HAVING failed_count >= :threshold
        """)

        results = db.session.execute(query, {'threshold': threshold}).mappings().all()
        for r in results:
            desc = f"Observed {r['failed_count']} denied/blocked connection events originating from {r['source_ip']} targeting {r['destination_ip']}."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"Repeated Denied/Failed Connections from {r['source_ip']}",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip=r['destination_ip'],
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['failed_count']),
                confidence='MEDIUM',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-004: Unusual External Communication
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_unusual_external(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        concat_sql = "GROUP_CONCAT(id) as event_ids" if cls._is_sqlite() else "GROUP_CONCAT(id SEPARATOR ',') as event_ids"
        query = text(f"""
            SELECT source_ip, destination_ip, hostname, domain,
                   COUNT(*) as conn_count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   {concat_sql}
            FROM network_events
            WHERE (source_ip LIKE '10.%' OR source_ip LIKE '192.168.%')
              AND destination_ip NOT LIKE '10.%' 
              AND destination_ip NOT LIKE '192.168.%'
              AND destination_ip NOT LIKE '172.1%'
              AND destination_ip NOT LIKE '127.%'
            {upload_clause}
            GROUP BY source_ip, destination_ip, hostname, domain
            HAVING conn_count >= :threshold
        """)

        results = db.session.execute(query, {'threshold': threshold}).mappings().all()
        for r in results:
            domain_info = f" ({r['domain']})" if r['domain'] else ""
            desc = f"Internal host {r['source_ip']} established {r['conn_count']} outbound sessions to external IP {r['destination_ip']}{domain_info}."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"Unusual Outbound Telemetry to {r['destination_ip']}",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip=r['destination_ip'],
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['conn_count']),
                confidence='MEDIUM',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-005: Suspicious Remote-Service Activity
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_remote_services(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        concat_sql = "GROUP_CONCAT(id) as event_ids" if cls._is_sqlite() else "GROUP_CONCAT(id SEPARATOR ',') as event_ids"
        query = text(f"""
            SELECT source_ip, destination_ip, destination_port, hostname,
                   COUNT(*) as conn_count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   {concat_sql}
            FROM network_events
            WHERE destination_port IN (22, 3389, 445, 5985, 5986)
            {upload_clause}
            GROUP BY source_ip, destination_ip, destination_port, hostname
            HAVING conn_count >= :threshold
        """)

        results = db.session.execute(query, {'threshold': threshold}).mappings().all()
        for r in results:
            port = r['destination_port']
            service_names = {
                22: 'SSH (Port 22)',
                3389: 'RDP (Port 3389)',
                445: 'SMB / RPC (Port 445)',
                5985: 'WinRM (Port 5985)',
                5986: 'WinRM (Port 5986)'
            }
            svc = service_names.get(port, f"Remote Service (Port {port})")
            desc = f"Observed {r['conn_count']} connection events to {svc} between {r['source_ip']} and {r['destination_ip']}."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"Suspicious {svc} Activity",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip=r['destination_ip'],
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['conn_count']),
                confidence='HIGH',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-006: Large Outbound Transfer
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_large_transfer(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        query = text(f"""
            SELECT id, source_ip, destination_ip, hostname, bytes_sent, timestamp
            FROM network_events
            WHERE bytes_sent >= :threshold
            {upload_clause}
        """)

        results = db.session.execute(query, {'threshold': threshold}).mappings().all()
        for r in results:
            mb = round(r['bytes_sent'] / (1024 * 1024), 2)
            desc = f"Egress transfer of {mb} MB ({r['bytes_sent']} bytes) detected from {r['source_ip']} to {r['destination_ip']}."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"Large Outbound Transfer ({mb} MB) from {r['hostname'] or r['source_ip']}",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip=r['destination_ip'],
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['timestamp'],
                last_seen=r['timestamp'],
                event_count=1,
                confidence='HIGH',
                event_ids=[str(r['id'])]
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-007: DNS Burst
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_dns_burst(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        if cls._is_sqlite():
            query = text(f"""
                SELECT source_ip, hostname,
                       COUNT(*) as query_count,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       GROUP_CONCAT(id) as event_ids
                FROM network_events
                WHERE (destination_port = 53 OR event_type = 'dns_query' OR dns_query IS NOT NULL)
                {upload_clause}
                GROUP BY source_ip, hostname
                HAVING query_count >= :threshold
                   AND ((julianday(last_seen) - julianday(first_seen)) * 86400) <= :window
            """)
        else:
            query = text(f"""
                SELECT source_ip, hostname,
                       COUNT(*) as query_count,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       GROUP_CONCAT(id SEPARATOR ',') as event_ids
                FROM network_events
                WHERE (destination_port = 53 OR event_type = 'dns_query' OR dns_query IS NOT NULL)
                {upload_clause}
                GROUP BY source_ip, hostname
                HAVING query_count >= :threshold
                   AND TIMESTAMPDIFF(SECOND, first_seen, last_seen) <= :window
            """)

        results = db.session.execute(query, {'threshold': threshold, 'window': max(window, 1)}).mappings().all()
        for r in results:
            desc = f"Host {r['source_ip']} issued {r['query_count']} DNS requests in quick succession."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title=f"DNS Query Burst from {r['hostname'] or r['source_ip']}",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip='DNS Resolver',
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['query_count']),
                confidence='MEDIUM',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-008: Repeated Connection Pattern (Beaconing)
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_beacon_pattern(cls, rule, upload_id, threshold, window):
        alerts = []
        upload_clause = f"AND upload_id = {int(upload_id)}" if upload_id else ""
        if cls._is_sqlite():
            query = text(f"""
                SELECT source_ip, destination_ip, hostname,
                       COUNT(*) as conn_count,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       GROUP_CONCAT(id) as event_ids
                FROM network_events
                WHERE (destination_ip NOT LIKE '10.%' AND destination_ip NOT LIKE '192.168.%' AND destination_ip NOT LIKE '172.1%')
                {upload_clause}
                GROUP BY source_ip, destination_ip, hostname
                HAVING conn_count >= :threshold
                   AND ((julianday(last_seen) - julianday(first_seen)) * 86400) <= :window
            """)
        else:
            query = text(f"""
                SELECT source_ip, destination_ip, hostname,
                       COUNT(*) as conn_count,
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       GROUP_CONCAT(id SEPARATOR ',') as event_ids
                FROM network_events
                WHERE (destination_ip NOT LIKE '10.%' AND destination_ip NOT LIKE '192.168.%' AND destination_ip NOT LIKE '172.1%')
                {upload_clause}
                GROUP BY source_ip, destination_ip, hostname
                HAVING conn_count >= :threshold
                   AND TIMESTAMPDIFF(SECOND, first_seen, last_seen) <= :window
            """)

        results = db.session.execute(query, {'threshold': threshold, 'window': max(window, 1)}).mappings().all()
        for r in results:
            desc = f"Endpoint {r['source_ip']} initiated {r['conn_count']} recurring sessions to external target {r['destination_ip']} within {window}s."
            alert_id = cls._create_or_update_alert(
                rule_id=rule.id,
                title="Repeated Periodic Connection Pattern (Beaconing Indicator)",
                description=desc,
                severity=rule.severity,
                source_ip=r['source_ip'],
                destination_ip=r['destination_ip'],
                endpoint=r['hostname'] or r['source_ip'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['conn_count']),
                confidence='HIGH',
                event_ids=r['event_ids'].split(',') if r['event_ids'] else []
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # RULE-009: Multiple Detection Combination
    # -------------------------------------------------------------------------
    @classmethod
    def _detect_multi_detections(cls):
        alerts = []
        concat_rules = "GROUP_CONCAT(DISTINCT rule_id) as triggered_rules" if cls._is_sqlite() else "GROUP_CONCAT(DISTINCT rule_id SEPARATOR ', ') as triggered_rules"
        query = text(f"""
            SELECT endpoint, source_ip,
                   COUNT(DISTINCT rule_id) as rule_count,
                   {concat_rules},
                   MIN(first_seen) as first_seen,
                   MAX(last_seen) as last_seen,
                   SUM(event_count) as total_events
            FROM alerts
            WHERE rule_id != 'RULE-009'
            GROUP BY endpoint, source_ip
            HAVING rule_count >= 2
        """)

        results = db.session.execute(query).mappings().all()
        for r in results:
            desc = f"Correlated incident: Endpoint {r['endpoint']} triggered {r['rule_count']} different threat rules ({r['triggered_rules']}). Escalated priority."
            alert_id = cls._create_or_update_alert(
                rule_id='RULE-009',
                title=f"Multiple Threat Detections on {r['endpoint'] or r['source_ip']}",
                description=desc,
                severity='CRITICAL',
                source_ip=r['source_ip'],
                destination_ip='Multiple Targets',
                endpoint=r['endpoint'],
                first_seen=r['first_seen'],
                last_seen=r['last_seen'],
                event_count=int(r['total_events']),
                confidence='HIGH',
                event_ids=[]
            )
            if alert_id:
                alerts.append(alert_id)
        return alerts

    # -------------------------------------------------------------------------
    # Alert Creation / Deduplication Helper
    # -------------------------------------------------------------------------
    @classmethod
    def _create_or_update_alert(cls, rule_id, title, description, severity, source_ip, destination_ip,
                                endpoint, first_seen, last_seen, event_count, confidence, event_ids):
        if isinstance(first_seen, str):
            try:
                first_seen = datetime.fromisoformat(first_seen.replace(' ', 'T'))
            except Exception:
                first_seen = datetime.now(timezone.utc)
        elif first_seen is None:
            first_seen = datetime.now(timezone.utc)

        if isinstance(last_seen, str):
            try:
                last_seen = datetime.fromisoformat(last_seen.replace(' ', 'T'))
            except Exception:
                last_seen = datetime.now(timezone.utc)
        elif last_seen is None:
            last_seen = datetime.now(timezone.utc)

        # Deduplication check for active alerts
        existing = Alert.query.filter(
            Alert.rule_id == rule_id,
            Alert.source_ip == source_ip,
            Alert.status.in_(['NEW', 'TRIAGED', 'INVESTIGATING'])
        ).first()

        if existing:
            existing.last_seen = last_seen
            existing.event_count = (existing.event_count or 0) + event_count
            db.session.commit()

            # Associate any new events
            if event_ids:
                for eid in event_ids:
                    eid_clean = eid.strip() if isinstance(eid, str) else eid
                    if eid_clean and str(eid_clean).isdigit():
                        int_eid = int(eid_clean)
                        if not AlertEvent.query.filter_by(alert_id=existing.id, event_id=int_eid).first():
                            db.session.add(AlertEvent(alert_id=existing.id, event_id=int_eid))
                db.session.commit()
            return None  # Aggregated into existing

        new_id = generate_next_alert_id()
        alert = Alert(
            id=new_id,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            endpoint=endpoint,
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=event_count,
            status='NEW',
            confidence=confidence
        )
        db.session.add(alert)
        db.session.commit()

        if event_ids:
            for eid in event_ids:
                eid_clean = eid.strip() if isinstance(eid, str) else eid
                if eid_clean and str(eid_clean).isdigit():
                    db.session.add(AlertEvent(alert_id=new_id, event_id=int(eid_clean)))
            db.session.commit()

        AuditService.log(
            action='ALERT_CREATE',
            entity_type='ALERT',
            entity_id=new_id,
            details=f"Generated {severity} alert: {title}"
        )
        return new_id

    @staticmethod
    def sync_endpoint_alert_counts():
        """Updates alert_count on endpoints based on alert table."""
        endpoints = Endpoint.query.all()
        for ep in endpoints:
            count = Alert.query.filter(
                (Alert.endpoint == ep.hostname) | (Alert.source_ip == ep.ip_address)
            ).count()
            ep.alert_count = count
        db.session.commit()
