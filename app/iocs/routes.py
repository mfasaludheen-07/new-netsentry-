from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.iocs import bp
from app.models import IOC, NetworkEvent, Case
from app.decorators import role_required
from app.services.ioc_service import IOCService
from app.services.audit_service import AuditService


@bp.route('/iocs')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    ioc_type = request.args.get('type', '').strip().upper()
    status = request.args.get('status', '').strip().upper()
    q = request.args.get('q', '').strip()

    query = IOC.query

    if ioc_type in IOCService.VALID_TYPES:
        query = query.filter_by(type=ioc_type)

    if status in IOCService.VALID_STATUSES:
        query = query.filter_by(status=status)

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (IOC.value.ilike(search_filter)) |
            (IOC.notes.ilike(search_filter))
        )

    iocs_pagination = query.order_by(IOC.last_seen.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('iocs/index.html', iocs_pagination=iocs_pagination, ioc_type=ioc_type, status=status, q=q)


@bp.route('/iocs/<int:ioc_id>')
@login_required
def view(ioc_id):
    ioc = db.session.get(IOC, ioc_id)
    if not ioc:
        abort(404)

    # Telemetry hits
    telemetry_events = []
    if ioc.type == 'IP':
        telemetry_events = NetworkEvent.query.filter(
            (NetworkEvent.source_ip == ioc.value) | (NetworkEvent.destination_ip == ioc.value)
        ).order_by(NetworkEvent.timestamp.desc()).limit(50).all()
    elif ioc.type == 'DOMAIN':
        telemetry_events = NetworkEvent.query.filter(
            (NetworkEvent.domain == ioc.value) | (NetworkEvent.dns_query == ioc.value)
        ).order_by(NetworkEvent.timestamp.desc()).limit(50).all()

    associated_cases = ioc.cases.all()
    classification = IOCService.classify_ip(ioc.value) if ioc.type == 'IP' else None

    return render_template(
        'iocs/view.html',
        ioc=ioc,
        telemetry_events=telemetry_events,
        associated_cases=associated_cases,
        classification=classification
    )


@bp.route('/iocs/add', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def add():
    value = request.form.get('value', '').strip()
    ioc_type = request.form.get('type', 'DOMAIN').strip().upper()
    notes = request.form.get('notes', '').strip()

    if value:
        ioc_id = IOCService.observe_ioc(value=value, ioc_type=ioc_type, notes=notes)
        if ioc_id:
            AuditService.log(
                action='IOC_UPDATE',
                user_id=current_user.id,
                entity_type='IOC',
                entity_id=str(ioc_id),
                details=f"Manually registered IOC {value} ({ioc_type})"
            )
            flash(f"Indicator '{value}' saved to IOC vault.", "success")
            return redirect(url_for('iocs.view', ioc_id=ioc_id))

    flash("Failed to register IOC. Check input value.", "warning")
    return redirect(url_for('iocs.index'))


@bp.route('/iocs/<int:ioc_id>/status', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def update_status(ioc_id):
    ioc = db.session.get(IOC, ioc_id)
    if not ioc:
        abort(404)

    status = request.form.get('status', '').strip().upper()
    confidence = request.form.get('confidence', '').strip().upper()
    notes = request.form.get('notes', '').strip()

    if IOCService.update_status(ioc_id, status, confidence, notes=notes or None, user_id=current_user.id):
        flash(f"IOC triage updated: {status} ({confidence} confidence).", "success")
    else:
        flash("Invalid status or confidence parameters.", "danger")

    return redirect(url_for('iocs.view', ioc_id=ioc.id))
