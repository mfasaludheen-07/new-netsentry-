import os
from flask import render_template, redirect, url_for, flash, request, send_file, abort, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.evidence import bp
from app.evidence.forms import EvidenceUploadForm
from app.models import Evidence, Case
from app.decorators import role_required
from app.services.evidence_service import EvidenceService
from app.services.audit_service import AuditService


@bp.route('/evidence')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()

    query = Evidence.query

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (Evidence.original_filename.ilike(search_filter)) |
            (Evidence.description.ilike(search_filter)) |
            (Evidence.hash_sha256.ilike(search_filter)) |
            (Evidence.case_id.ilike(search_filter))
        )

    evidence_pagination = query.order_by(Evidence.uploaded_at.desc()).paginate(page=page, per_page=15, error_out=False)
    cases = Case.query.filter(Case.status.in_(['OPEN', 'INVESTIGATING'])).all()

    return render_template('evidence/index.html', evidence_pagination=evidence_pagination, q=q, cases=cases)


@bp.route('/evidence/upload/<case_id>', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def upload(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    form = EvidenceUploadForm()
    if form.validate_on_submit():
        file = form.evidence_file.data
        desc = form.description.data

        res = EvidenceService.store_evidence(
            case_id=case.id,
            uploaded_file=file,
            user_id=current_user.id,
            description=desc
        )

        if res['success']:
            flash(f"Forensic artifact '{file.filename}' secured. SHA-256: {res['sha256']}", "success")
        else:
            flash(f"Upload failed: {res['message']}", "danger")
    else:
        flash("Invalid evidence upload form.", "warning")

    return redirect(url_for('cases.view', case_id=case.id, tab='evidence'))


@bp.route('/evidence/<int:evidence_id>/download')
@login_required
@role_required('ADMIN', 'ANALYST')
def download(evidence_id):
    evidence = db.session.get(Evidence, evidence_id)
    if not evidence:
        abort(404)

    file_path = os.path.join(current_app.config['EVIDENCE_FOLDER'], evidence.stored_filename)
    if not os.path.exists(file_path):
        flash("Physical evidence file missing from repository storage.", "danger")
        return redirect(url_for('evidence.index'))

    # Log chain of custody
    EvidenceService.log_chain(
        evidence_id=evidence.id,
        user_id=current_user.id,
        action='DOWNLOADED',
        current_hash=evidence.hash_sha256
    )

    AuditService.log(
        action='EVIDENCE_DOWNLOAD',
        user_id=current_user.id,
        entity_type='EVIDENCE',
        entity_id=str(evidence.id),
        details=f"Downloaded evidence {evidence.original_filename} (SHA-256: {evidence.hash_sha256})"
    )

    return send_file(
        file_path,
        as_attachment=True,
        download_name=evidence.original_filename,
        mimetype=evidence.mime_type
    )


@bp.route('/evidence/<int:evidence_id>/verify', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def verify(evidence_id):
    evidence = db.session.get(Evidence, evidence_id)
    if not evidence:
        abort(404)

    res = EvidenceService.verify_integrity(evidence.id)
    if res['valid']:
        flash(f"Integrity PASS: SHA-256 {res['actual_hash']} matches recorded baseline.", "success")
    else:
        flash(f"Integrity ALERT: {res['message']}", "danger")

    return redirect(url_for('cases.view', case_id=evidence.case_id, tab='evidence'))
