from datetime import datetime, timezone
from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.alerts import bp
from app.models import Alert, Case, CaseAlert, NetworkEvent, DetectionRule
from app.decorators import role_required
from app.services.audit_service import AuditService
from app.services.detection_engine import DetectionEngine


@bp.route('/alerts', strict_slashes=False)
@bp.route('/alerts/', strict_slashes=False)
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '').strip().upper()
    status = request.args.get('status', '').strip().upper()
    q = request.args.get('q', '').strip()

    query = Alert.query

    if severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        query = query.filter_by(severity=severity)

    if status in ('NEW', 'TRIAGED', 'INVESTIGATING', 'FALSE_POSITIVE', 'RESOLVED'):
        query = query.filter_by(status=status)

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (Alert.title.ilike(search_filter)) |
            (Alert.description.ilike(search_filter)) |
            (Alert.source_ip.ilike(search_filter)) |
            (Alert.destination_ip.ilike(search_filter)) |
            (Alert.endpoint.ilike(search_filter)) |
            (Alert.id.ilike(search_filter))
        )

    alerts_pagination = query.order_by(Alert.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    open_cases = Case.query.filter(Case.status.in_(['OPEN', 'INVESTIGATING'])).all()

    return render_template(
        'alerts/index.html',
        alerts_pagination=alerts_pagination,
        severity=severity,
        status=status,
        q=q,
        open_cases=open_cases
    )


@bp.route('/alerts/<alert_id>')
@login_required
def view(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)

    events = alert.events.order_by(NetworkEvent.timestamp.asc()).all()
    associated_cases = alert.cases.all()
    available_cases = Case.query.filter(Case.status.in_(['OPEN', 'INVESTIGATING'])).all()

    return render_template(
        'alerts/view.html',
        alert=alert,
        events=events,
        associated_cases=associated_cases,
        available_cases=available_cases
    )


@bp.route('/alerts/<alert_id>/triage', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def triage(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)

    new_status = request.form.get('status', '').strip().upper()
    valid_statuses = {'NEW', 'TRIAGED', 'INVESTIGATING', 'FALSE_POSITIVE', 'RESOLVED'}
    if new_status in valid_statuses:
        old_status = alert.status
        alert.status = new_status
        alert.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        AuditService.log(
            action='ALERT_UPDATE',
            user_id=current_user.id,
            entity_type='ALERT',
            entity_id=alert.id,
            details=f"Triage status changed from {old_status} to {new_status}"
        )
        flash(f"Alert {alert.id} status updated to {new_status}.", "success")
    else:
        flash("Invalid triage status specified.", "warning")

    return redirect(url_for('alerts.view', alert_id=alert.id))


@bp.route('/alerts/<alert_id>/attach-case', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def attach_case(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)

    case_id = request.form.get('case_id', '').strip()
    case = db.session.get(Case, case_id)
    if not case:
        flash("Specified case was not found.", "danger")
        return redirect(url_for('alerts.view', alert_id=alert.id))

    if not CaseAlert.query.filter_by(case_id=case.id, alert_id=alert.id).first():
        db.session.add(CaseAlert(case_id=case.id, alert_id=alert.id))
        alert.status = 'INVESTIGATING'
        db.session.commit()

        AuditService.log(
            action='CASE_UPDATE',
            user_id=current_user.id,
            entity_type='CASE',
            entity_id=case.id,
            details=f"Attached alert {alert.id} to investigation case {case.id}"
        )
        flash(f"Alert {alert.id} successfully attached to Case {case.id}.", "success")
    else:
        flash(f"Alert is already linked to Case {case.id}.", "info")

    return redirect(url_for('cases.view', case_id=case.id))


@bp.route('/alerts/run-detections', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def run_detections():
    results = DetectionEngine.run()
    flash(f"Detection engine evaluated all events. {results['total_alerts_generated']} alert(s) processed/generated.", "info")
    return redirect(url_for('alerts.index'))
