from datetime import datetime, timezone
from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.cases import bp
from app.models import (
    Case, User, Alert, CaseAlert, NetworkEvent, CaseEvent,
    IOC, CaseIOC, Endpoint, AttackStage, CaseMitre, MitreTechnique,
    Evidence, Finding, AnalystNote, Report, AuditLog, EventCorrelation
)
from app.decorators import role_required
from app.utils import generate_next_case_id
from app.services.timeline_service import TimelineService
from app.services.correlation_engine import CorrelationEngine
from app.services.audit_service import AuditService


@bp.route('/cases')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '').strip().upper()
    severity = request.args.get('severity', '').strip().upper()
    q = request.args.get('q', '').strip()

    query = Case.query

    if status in ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'):
        query = query.filter_by(status=status)

    if severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        query = query.filter_by(severity=severity)

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (Case.id.ilike(search_filter)) |
            (Case.title.ilike(search_filter)) |
            (Case.description.ilike(search_filter))
        )

    cases_pagination = query.order_by(Case.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('cases/index.html', cases_pagination=cases_pagination, status=status, severity=severity, q=q)


@bp.route('/cases/create', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def create():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'MEDIUM').strip().upper()
        priority = request.form.get('priority', 'MEDIUM').strip().upper()
        assigned_to = request.form.get('assigned_to', type=int)

        if not title:
            flash("Case title is required.", "danger")
            return render_template('cases/create.html', analysts=User.query.all())

        new_id = generate_next_case_id()
        case = Case(
            id=new_id,
            title=title,
            description=description,
            severity=severity if severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') else 'MEDIUM',
            priority=priority if priority in ('LOW', 'MEDIUM', 'HIGH', 'URGENT') else 'MEDIUM',
            status='OPEN',
            assigned_to=assigned_to or current_user.id,
            created_by=current_user.id,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(case)
        db.session.commit()

        # Add initial timeline marker
        TimelineService.add_event(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type='Case Creation',
            description=f"Investigation case {case.id} opened: {title}",
            severity='INFO',
            reference_type='CASE_STATUS',
            reference_id=case.id
        )

        AuditService.log(
            action='CASE_CREATE',
            user_id=current_user.id,
            entity_type='CASE',
            entity_id=case.id,
            details=f"Created investigation case {case.id}: {title}"
        )

        flash(f"Investigation Case {case.id} created successfully.", "success")
        return redirect(url_for('cases.view', case_id=case.id))

    analysts = User.query.filter(User.status == 'active').all()
    return render_template('cases/create.html', analysts=analysts)


@bp.route('/cases/<case_id>')
@login_required
def view(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    active_tab = request.args.get('tab', 'overview').lower()

    # Data for all 14 tabs
    alerts = case.alerts.all()
    events = case.events.order_by(NetworkEvent.timestamp.asc()).all()
    iocs = case.iocs.all()
    
    # Endpoints associated
    endpoints = Endpoint.query.filter(
        (Endpoint.hostname.in_([a.endpoint for a in alerts if a.endpoint])) |
        (Endpoint.ip_address.in_([a.source_ip for a in alerts if a.source_ip]))
    ).all()

    timeline_items = TimelineService.get_timeline(case_id)
    attack_stages = AttackStage.query.filter_by(case_id=case_id).order_by(AttackStage.stage_order.asc()).all()
    mitre_mappings = CaseMitre.query.filter_by(case_id=case_id).all()
    available_techniques = MitreTechnique.query.all()
    evidence_items = Evidence.query.filter_by(case_id=case_id).order_by(Evidence.uploaded_at.desc()).all()
    findings = Finding.query.filter_by(case_id=case_id).order_by(Finding.created_at.desc()).all()
    notes = AnalystNote.query.filter_by(case_id=case_id).order_by(AnalystNote.created_at.desc()).all()
    reports = Report.query.filter_by(case_id=case_id).order_by(Report.generated_at.desc()).all()
    correlations = EventCorrelation.query.filter_by(case_id=case_id).all()
    audit_trail = AuditLog.query.filter_by(entity_type='CASE', entity_id=case_id).order_by(AuditLog.timestamp.desc()).all()
    users = User.query.filter(User.status == 'active').all()

    return render_template(
        'cases/view.html',
        case=case,
        active_tab=active_tab,
        alerts=alerts,
        events=events,
        iocs=iocs,
        endpoints=endpoints,
        timeline_items=timeline_items,
        attack_stages=attack_stages,
        mitre_mappings=mitre_mappings,
        available_techniques=available_techniques,
        evidence_items=evidence_items,
        findings=findings,
        notes=notes,
        reports=reports,
        correlations=correlations,
        audit_trail=audit_trail,
        users=users
    )


@bp.route('/cases/<case_id>/status', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def update_status(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    new_status = request.form.get('status', '').strip().upper()
    new_severity = request.form.get('severity', '').strip().upper()
    new_priority = request.form.get('priority', '').strip().upper()
    assigned_to = request.form.get('assigned_to', type=int)

    if new_status in ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE'):
        old_status = case.status
        case.status = new_status
        if new_status in ('RESOLVED', 'CLOSED'):
            case.closed_at = datetime.now(timezone.utc)
        TimelineService.add_event(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type='Case Status Change',
            description=f"Status modified from {old_status} to {new_status}",
            severity='INFO',
            reference_type='CASE_STATUS',
            reference_id=case.id
        )

    if new_severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        case.severity = new_severity

    if new_priority in ('LOW', 'MEDIUM', 'HIGH', 'URGENT'):
        case.priority = new_priority

    if assigned_to:
        case.assigned_to = assigned_to

    case.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    AuditService.log(
        action='CASE_UPDATE',
        user_id=current_user.id,
        entity_type='CASE',
        entity_id=case.id,
        details=f"Updated status: {case.status}, severity: {case.severity}, priority: {case.priority}"
    )

    flash(f"Case {case.id} details updated.", "success")
    return redirect(url_for('cases.view', case_id=case.id, tab='overview'))


@bp.route('/cases/<case_id>/notes/add', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def add_note(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    note_text = request.form.get('note', '').strip()
    if note_text:
        note = AnalystNote(
            case_id=case.id,
            user_id=current_user.id,
            note=note_text,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(note)
        db.session.commit()

        TimelineService.add_event(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type='Analyst Note',
            description=f"Analyst {current_user.username} posted investigative note.",
            severity='INFO',
            reference_type='NOTE',
            reference_id=str(note.id)
        )

        AuditService.log(
            action='CASE_UPDATE',
            user_id=current_user.id,
            entity_type='CASE',
            entity_id=case.id,
            details=f"Added analyst note to case {case.id}"
        )
        flash("Analyst note appended.", "success")

    return redirect(url_for('cases.view', case_id=case.id, tab='notes'))


@bp.route('/cases/<case_id>/findings/add', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def add_finding(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    evidence = request.form.get('evidence', '').strip()
    confidence = request.form.get('confidence', 'MEDIUM').strip().upper()
    status = request.form.get('status', 'OBSERVED').strip().upper()

    if title and description:
        finding = Finding(
            case_id=case.id,
            title=title,
            description=description,
            evidence=evidence,
            confidence=confidence if confidence in ('LOW', 'MEDIUM', 'HIGH') else 'MEDIUM',
            status=status if status in ('OBSERVED', 'SUSPECTED', 'CONFIRMED', 'DISPROVED') else 'OBSERVED',
            created_by=current_user.id,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(finding)
        db.session.commit()

        TimelineService.add_event(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type='Analyst Finding',
            description=f"Finding registered: {title} ({status}, {confidence} confidence)",
            severity='MEDIUM',
            reference_type='FINDING',
            reference_id=str(finding.id)
        )

        AuditService.log(
            action='FINDING_CREATE',
            user_id=current_user.id,
            entity_type='CASE',
            entity_id=case.id,
            details=f"Added forensic finding '{title}' to case {case.id}"
        )
        flash(f"Finding '{title}' recorded.", "success")

    return redirect(url_for('cases.view', case_id=case.id, tab='findings'))


@bp.route('/cases/<case_id>/attack-stage/add', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def add_attack_stage(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    stage_name = request.form.get('stage_name', '').strip()
    status = request.form.get('status', 'SUSPECTED').strip().upper()
    confidence = request.form.get('confidence', 'MEDIUM').strip().upper()
    evidence_summary = request.form.get('evidence_summary', '').strip()
    analyst_comment = request.form.get('analyst_comment', '').strip()

    if stage_name:
        current_max = db.session.query(db.func.max(AttackStage.stage_order)).filter_by(case_id=case.id).scalar() or 0
        stage = AttackStage(
            case_id=case.id,
            stage_order=current_max + 1,
            stage_name=stage_name,
            status=status if status in ('OBSERVED', 'SUSPECTED', 'CONFIRMED', 'DISPROVED') else 'SUSPECTED',
            confidence=confidence if confidence in ('LOW', 'MEDIUM', 'HIGH') else 'MEDIUM',
            evidence_summary=evidence_summary,
            analyst_comment=analyst_comment,
            updated_by=current_user.id,
            updated_at=datetime.now(timezone.utc)
        )
        db.session.add(stage)
        db.session.commit()

        TimelineService.add_event(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type='Attack Path Stage',
            description=f"Attack progression stage mapped: {stage_name} ({status})",
            severity='HIGH',
            reference_type='ATTACK_STAGE',
            reference_id=str(stage.id)
        )

        AuditService.log(
            action='CASE_UPDATE',
            user_id=current_user.id,
            entity_type='CASE',
            entity_id=case.id,
            details=f"Added attack reconstruction stage '{stage_name}'"
        )
        flash(f"Attack Stage '{stage_name}' recorded.", "success")

    return redirect(url_for('cases.view', case_id=case.id, tab='attack_path'))


@bp.route('/cases/<case_id>/mitre/add', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def add_mitre(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    technique_id = request.form.get('technique_id', '').strip()
    status = request.form.get('status', 'SUSPECTED').strip().upper()
    notes = request.form.get('notes', '').strip()
    supporting_evidence = request.form.get('supporting_evidence', '').strip()

    technique = db.session.get(MitreTechnique, technique_id)
    if technique:
        existing = CaseMitre.query.filter_by(case_id=case.id, technique_id=technique_id).first()
        if existing:
            existing.status = status
            existing.notes = notes
            existing.supporting_evidence = supporting_evidence
            existing.updated_by = current_user.id
            existing.updated_at = datetime.now(timezone.utc)
        else:
            cm = CaseMitre(
                case_id=case.id,
                technique_id=technique_id,
                status=status if status in ('OBSERVED', 'SUSPECTED', 'NOT_APPLICABLE') else 'SUSPECTED',
                notes=notes,
                supporting_evidence=supporting_evidence,
                updated_by=current_user.id,
                updated_at=datetime.now(timezone.utc)
            )
            db.session.add(cm)

        db.session.commit()

        TimelineService.add_event(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type='MITRE ATT&CK Mapping',
            description=f"Mapped technique {technique.id} ({technique.name}) as {status}",
            severity='MEDIUM',
            reference_type='MITRE',
            reference_id=technique.id
        )

        AuditService.log(
            action='MITRE_ADD',
            user_id=current_user.id,
            entity_type='CASE',
            entity_id=case.id,
            details=f"Mapped MITRE technique {technique_id} ({technique.name}) to case {case.id}"
        )
        flash(f"MITRE ATT&CK technique {technique_id} mapped.", "success")

    return redirect(url_for('cases.view', case_id=case.id, tab='mitre'))


@bp.route('/cases/<case_id>/correlate', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def correlate(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    res = CorrelationEngine.correlate_events(case_id=case.id)
    flash(f"Correlation engine finished: {res['correlated_pairs']} related event linkages discovered.", "info")
    return redirect(url_for('cases.view', case_id=case.id, tab='overview'))
