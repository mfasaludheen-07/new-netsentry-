from flask import render_template, request
from flask_login import login_required
from app.timeline import bp
from app.services.timeline_service import TimelineService
from app.models import Case


@bp.route('/timeline')
@login_required
def index():
    case_id = request.args.get('case_id', '').strip()
    event_type = request.args.get('event_type', '').strip()
    severity = request.args.get('severity', '').strip().upper()
    search = request.args.get('search', '').strip()

    filters = {
        'event_type': event_type or None,
        'severity': severity if severity in ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') else None,
        'search': search or None
    }

    events = TimelineService.get_timeline(case_id=case_id or None, filters=filters)
    cases = Case.query.order_by(Case.created_at.desc()).all()

    return render_template(
        'timeline/index.html',
        events=events,
        cases=cases,
        selected_case_id=case_id,
        selected_type=event_type,
        selected_severity=severity,
        search=search
    )
