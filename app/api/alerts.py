from flask import jsonify, request
from flask_login import login_required, current_user
from app.api import bp
from app.models import Alert
from app.extensions import db
from app.decorators import role_required
from app.services.audit_service import AuditService


@bp.route('/alerts', methods=['GET'])
@login_required
def get_alerts():
    severity = request.args.get('severity')
    status = request.args.get('status')
    raw_limit = request.args.get('limit', 50, type=int)
    limit = max(1, min(raw_limit or 50, 200))

    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity.upper())
    if status:
        query = query.filter_by(status=status.upper())

    alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()

    return jsonify({
        'count': len(alerts),
        'alerts': [
            {
                'id': a.id,
                'rule_id': a.rule_id,
                'title': a.title,
                'severity': a.severity,
                'source_ip': a.source_ip,
                'destination_ip': a.destination_ip,
                'endpoint': a.endpoint,
                'status': a.status,
                'confidence': a.confidence,
                'event_count': a.event_count,
                'first_seen': str(a.first_seen),
                'last_seen': str(a.last_seen)
            } for a in alerts
        ]
    })


@bp.route('/alerts/triage', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def triage_alert():
    data = request.get_json() or {}
    alert_id = data.get('alert_id')
    new_status = data.get('status', '').upper()

    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    if new_status not in {'NEW', 'TRIAGED', 'INVESTIGATING', 'FALSE_POSITIVE', 'RESOLVED'}:
        return jsonify({'error': 'Invalid status'}), 400

    alert.status = new_status
    db.session.commit()

    AuditService.log(
        action='ALERT_UPDATE',
        user_id=current_user.id,
        entity_type='ALERT',
        entity_id=alert.id,
        details=f"API triage update: status changed to {new_status}"
    )

    return jsonify({'success': True, 'alert_id': alert.id, 'status': alert.status})
