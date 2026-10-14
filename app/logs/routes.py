import os
import mimetypes
from datetime import datetime, timezone
from flask import render_template, redirect, url_for, flash, request, current_app, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.logs import bp
from app.logs.forms import LogUploadForm
from app.models import LogUpload, LogSource, NetworkEvent
from app.decorators import role_required
from app.utils import safe_storage_filename, compute_file_sha256
from app.services.log_parser import LogParser
from app.services.detection_engine import DetectionEngine
from app.services.audit_service import AuditService


@bp.route('/logs')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    uploads_pagination = LogUpload.query.order_by(LogUpload.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    sources = LogSource.query.all()
    total_events = NetworkEvent.query.count()
    return render_template('logs/index.html', uploads_pagination=uploads_pagination, sources=sources, total_events=total_events)


@bp.route('/logs/upload', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def upload():
    form = LogUploadForm()
    if form.validate_on_submit():
        file = form.log_file.data
        if not file or not file.filename:
            flash("No file was selected for upload.", "warning")
            return render_template('logs/upload.html', form=form)

        orig_filename = os.path.basename(file.filename)
        ext = os.path.splitext(orig_filename)[1].lower().replace('.', '')

        if ext not in current_app.config['ALLOWED_LOG_EXTENSIONS']:
            flash(f"Disallowed file extension .{ext}. Permitted formats: {', '.join(current_app.config['ALLOWED_LOG_EXTENSIONS'])}", "danger")
            return render_template('logs/upload.html', form=form)

        storage_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(storage_folder, exist_ok=True)

        stored_filename = f"log_{safe_storage_filename(orig_filename)}"
        dest_path = os.path.join(storage_folder, stored_filename)

        file.save(dest_path)
        file_size = os.path.getsize(dest_path)

        if file_size > current_app.config['MAX_CONTENT_LENGTH']:
            os.remove(dest_path)
            flash(f"File size exceeds maximum limit of {current_app.config['MAX_UPLOAD_MB']} MB.", "danger")
            return render_template('logs/upload.html', form=form)

        sha256_hash = compute_file_sha256(dest_path)
        mime_type = mimetypes.guess_type(orig_filename)[0] or 'text/plain'

        # Check or create default LogSource
        source_type = form.source_type.data
        source = LogSource.query.filter_by(source_type=source_type).first()
        if not source:
            source = LogSource(
                name=f"{source_type} Feed",
                source_type=source_type,
                description=f"Automated ingestion source for {source_type}",
                timezone=form.timezone.data or 'UTC',
                created_by=current_user.id
            )
            db.session.add(source)
            db.session.commit()

        upload_record = LogUpload(
            source_id=source.id,
            original_filename=orig_filename,
            stored_filename=stored_filename,
            file_size=file_size,
            mime_type=mime_type,
            hash_sha256=sha256_hash,
            status='PENDING',
            uploaded_by=current_user.id,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(upload_record)
        db.session.commit()

        AuditService.log(
            action='LOG_UPLOAD',
            user_id=current_user.id,
            entity_type='LOG_UPLOAD',
            entity_id=str(upload_record.id),
            details=f"Uploaded telemetry file {orig_filename} ({file_size} bytes, SHA-256: {sha256_hash})"
        )

        # Parse and Normalize
        parse_results = LogParser.parse_file(
            upload_id=upload_record.id,
            file_path=dest_path,
            source_type=source_type,
            timezone_str=form.timezone.data or 'UTC'
        )

        # Execute Detection Engine against newly ingested telemetry
        detection_results = DetectionEngine.run(upload_id=upload_record.id)
        alert_count = detection_results.get('total_alerts_generated', 0)

        flash(
            f"Telemetry ingested: {parse_results['imported']} events normalized, {parse_results['skipped']} skipped. "
            f"Detection engine triggered {alert_count} alert(s).",
            "success"
        )
        return redirect(url_for('logs.view_upload', upload_id=upload_record.id))

    return render_template('logs/upload.html', form=form)


@bp.route('/logs/<int:upload_id>')
@login_required
def view_upload(upload_id):
    upload = db.session.get(LogUpload, upload_id)
    if not upload:
        abort(404)

    page = request.args.get('page', 1, type=int)
    events_pagination = NetworkEvent.query.filter_by(upload_id=upload_id).order_by(NetworkEvent.timestamp.asc()).paginate(page=page, per_page=20, error_out=False)

    return render_template('logs/view.html', upload=upload, events_pagination=events_pagination)


@bp.route('/traffic')
@login_required
def traffic():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip()
    source_ip = request.args.get('source_ip', '').strip()
    destination_ip = request.args.get('destination_ip', '').strip()
    port = request.args.get('port', type=int)
    protocol = request.args.get('protocol', '').strip().upper()
    action = request.args.get('action', '').strip().upper()

    query = NetworkEvent.query

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (NetworkEvent.source_ip.ilike(search_filter)) |
            (NetworkEvent.destination_ip.ilike(search_filter)) |
            (NetworkEvent.hostname.ilike(search_filter)) |
            (NetworkEvent.domain.ilike(search_filter)) |
            (NetworkEvent.username.ilike(search_filter))
        )

    if source_ip:
        query = query.filter(NetworkEvent.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NetworkEvent.destination_ip == destination_ip)
    if port:
        query = query.filter((NetworkEvent.source_port == port) | (NetworkEvent.destination_port == port))
    if protocol:
        query = query.filter(NetworkEvent.protocol == protocol)
    if action:
        query = query.filter(NetworkEvent.action == action)

    events_pagination = query.order_by(NetworkEvent.timestamp.desc()).paginate(page=page, per_page=25, error_out=False)

    return render_template(
        'logs/traffic.html',
        events_pagination=events_pagination,
        q=q,
        source_ip=source_ip,
        destination_ip=destination_ip,
        port=port,
        protocol=protocol,
        action=action
    )


@bp.route('/traffic/<int:event_id>')
@login_required
def traffic_detail(event_id):
    event = db.session.get(NetworkEvent, event_id)
    if not event:
        abort(404)
    return render_template('logs/traffic_detail.html', event=event)
