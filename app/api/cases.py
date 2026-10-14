from flask import jsonify, request
from flask_login import login_required, current_user
from app.api import bp
from app.models import Case
from app.extensions import db
from app.decorators import role_required
from app.utils import generate_next_case_id
from app.services.audit_service import AuditService


@bp.route('/cases', methods=['GET'])
@login_required
def get_cases():
    status = request.args.get('status')
    raw_limit = request.args.get('limit', 50, type=int)
    limit = max(1, min(raw_limit or 50, 200))

    query = Case.query
    if status:
        query = query.filter_by(status=status.upper())

    cases = query.order_by(Case.created_at.desc()).limit(limit).all()

    return jsonify({
        'count': len(cases),
        'cases': [
            {
                'id': c.id,
                'title': c.title,
                'severity': c.severity,
                'priority': c.priority,
                'status': c.status,
                'assigned_to': c.assignee.username if c.assignee else None,
                'created_by': c.creator.username if c.creator else None,
                'created_at': str(c.created_at)
            } for c in cases
        ]
    })


@bp.route('/cases', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def create_case():
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    if not title:
        return jsonify({'error': 'Title is required'}), 400

    new_id = generate_next_case_id()
    case = Case(
        id=new_id,
        title=title,
        description=data.get('description', ''),
        severity=data.get('severity', 'MEDIUM').upper(),
        priority=data.get('priority', 'MEDIUM').upper(),
        status='OPEN',
        assigned_to=data.get('assigned_to') or current_user.id,
        created_by=current_user.id
    )
    db.session.add(case)
    db.session.commit()

    AuditService.log(
        action='CASE_CREATE',
        user_id=current_user.id,
        entity_type='CASE',
        entity_id=case.id,
        details=f"API created investigation case {case.id}: {title}"
    )

    return jsonify({'success': True, 'case_id': case.id}), 201
