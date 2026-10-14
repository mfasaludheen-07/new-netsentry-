from datetime import datetime, date, timedelta, timezone
from flask import render_template, redirect, url_for, jsonify
from flask_login import login_required
from sqlalchemy import func, desc
from app.extensions import db
from app.dashboard import bp
from app.models import NetworkEvent, Alert, Case, IOC, Endpoint, Evidence, LogUpload


@bp.route('/')
def root():
    return redirect(url_for('dashboard.index'))


@bp.route('/dashboard')
@login_required
def index():
    # 1. High-level metric KPI counters
    total_events = NetworkEvent.query.count()
    
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_events = NetworkEvent.query.filter(NetworkEvent.timestamp >= today_start).count()
    if today_events == 0 and total_events > 0:
        # Fallback to recent events count if test dataset is historical
        today_events = NetworkEvent.query.filter(NetworkEvent.timestamp >= datetime.now() - timedelta(days=30)).count()

    total_alerts = Alert.query.count()
    critical_alerts = Alert.query.filter_by(severity='CRITICAL').count()
    open_cases = Case.query.filter(Case.status.in_(['OPEN', 'INVESTIGATING'])).count()
    total_iocs = IOC.query.count()
    total_endpoints = Endpoint.query.count()
    total_evidence = Evidence.query.count()

    # 2. Alerts by Severity
    severity_counts = dict(
        db.session.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    )
    chart_severity = {
        'CRITICAL': severity_counts.get('CRITICAL', 0),
        'HIGH': severity_counts.get('HIGH', 0),
        'MEDIUM': severity_counts.get('MEDIUM', 0),
        'LOW': severity_counts.get('LOW', 0),
    }

    # 3. Protocol Distribution
    proto_data = db.session.query(
        NetworkEvent.protocol, func.count(NetworkEvent.id)
    ).group_by(NetworkEvent.protocol).order_by(desc(func.count(NetworkEvent.id))).limit(6).all()
    chart_protocols = {p[0] or 'Other': p[1] for p in proto_data}

    # 4. Top Source IPs
    top_src_ips = db.session.query(
        NetworkEvent.source_ip, func.count(NetworkEvent.id)
    ).group_by(NetworkEvent.source_ip).order_by(desc(func.count(NetworkEvent.id))).limit(5).all()

    # 5. Top Destination Ports
    top_ports = db.session.query(
        NetworkEvent.destination_port, func.count(NetworkEvent.id)
    ).filter(NetworkEvent.destination_port.isnot(None)).group_by(NetworkEvent.destination_port).order_by(desc(func.count(NetworkEvent.id))).limit(5).all()

    # 6. Case Status Breakdown
    case_status_data = dict(
        db.session.query(Case.status, func.count(Case.id)).group_by(Case.status).all()
    )
    chart_case_statuses = {
        'OPEN': case_status_data.get('OPEN', 0),
        'INVESTIGATING': case_status_data.get('INVESTIGATING', 0),
        'CONTAINED': case_status_data.get('CONTAINED', 0),
        'RESOLVED': case_status_data.get('RESOLVED', 0),
        'CLOSED': case_status_data.get('CLOSED', 0),
    }

    # 7. Recent Items
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    recent_cases = Case.query.order_by(Case.created_at.desc()).limit(5).all()
    recent_events = NetworkEvent.query.order_by(NetworkEvent.timestamp.desc()).limit(6).all()

    return render_template(
        'dashboard.html',
        total_events=total_events,
        today_events=today_events,
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        open_cases=open_cases,
        total_iocs=total_iocs,
        total_endpoints=total_endpoints,
        total_evidence=total_evidence,
        chart_severity=chart_severity,
        chart_protocols=chart_protocols,
        top_src_ips=top_src_ips,
        top_ports=top_ports,
        chart_case_statuses=chart_case_statuses,
        recent_alerts=recent_alerts,
        recent_cases=recent_cases,
        recent_events=recent_events
    )
