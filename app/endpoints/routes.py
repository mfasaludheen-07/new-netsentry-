from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.endpoints import bp
from app.models import Endpoint, NetworkEvent, Alert, Case
from app.decorators import role_required
from app.services.audit_service import AuditService


@bp.route('/endpoints')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    criticality = request.args.get('criticality', '').strip().upper()
    q = request.args.get('q', '').strip()

    query = Endpoint.query

    if criticality in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        query = query.filter_by(criticality=criticality)

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (Endpoint.hostname.ilike(search_filter)) |
            (Endpoint.ip_address.ilike(search_filter)) |
            (Endpoint.owner_description.ilike(search_filter))
        )

    endpoints_pagination = query.order_by(Endpoint.alert_count.desc(), Endpoint.last_seen.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('endpoints/index.html', endpoints_pagination=endpoints_pagination, criticality=criticality, q=q)


@bp.route('/endpoints/<target>')
@login_required
def view(target):
    # Find either by integer ID or by hostname string
    endpoint = None
    if target.isdigit():
        endpoint = db.session.get(Endpoint, int(target))
    if not endpoint:
        endpoint = Endpoint.query.filter_by(hostname=target).first()

    if not endpoint:
        abort(404)

    # Telemetry events for this endpoint
    events = NetworkEvent.query.filter(
        (NetworkEvent.hostname == endpoint.hostname) |
        (NetworkEvent.source_ip == endpoint.ip_address) |
        (NetworkEvent.destination_ip == endpoint.ip_address)
    ).order_by(NetworkEvent.timestamp.desc()).limit(100).all()

    # Alerts involving this endpoint
    alerts = Alert.query.filter(
        (Alert.endpoint == endpoint.hostname) |
        (Alert.source_ip == endpoint.ip_address)
    ).order_by(Alert.created_at.desc()).all()

    # Cases involving this endpoint
    cases = Case.query.filter(
        Case.alerts.any(
            (Alert.endpoint == endpoint.hostname) | (Alert.source_ip == endpoint.ip_address)
        )
    ).all()

    return render_template(
        'endpoints/view.html',
        endpoint=endpoint,
        events=events,
        alerts=alerts,
        cases=cases
    )


@bp.route('/endpoints/<int:endpoint_id>/edit', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def edit(endpoint_id):
    endpoint = db.session.get(Endpoint, endpoint_id)
    if not endpoint:
        abort(404)

    criticality = request.form.get('criticality', '').strip().upper()
    owner_description = request.form.get('owner_description', '').strip()
    os_info = request.form.get('os_info', '').strip()

    if criticality in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        endpoint.criticality = criticality
    if owner_description:
        endpoint.owner_description = owner_description
    if os_info:
        endpoint.os_info = os_info

    db.session.commit()
    AuditService.log(
        action='SETTINGS_UPDATE',
        user_id=current_user.id,
        entity_type='ENDPOINT',
        entity_id=str(endpoint.id),
        details=f"Updated endpoint profile {endpoint.hostname} ({endpoint.criticality})"
    )
    flash(f"Endpoint profile for {endpoint.hostname} updated.", "success")
    return redirect(url_for('endpoints.view', target=endpoint.id))
