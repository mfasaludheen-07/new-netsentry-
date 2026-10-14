from datetime import datetime, timezone
from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from app.extensions import db
from app.admin import bp
from app.models import User, Role, DetectionRule, AuditLog, Setting
from app.decorators import role_required
from app.services.audit_service import AuditService


@bp.route('/users', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
def users():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            role_id = request.form.get('role_id', type=int)

            if not username or not email or not password or not role_id:
                flash("All user fields are required.", "danger")
            elif User.query.filter((User.username == username) | (User.email == email)).first():
                flash("A user with this username or email already exists.", "warning")
            else:
                new_user = User(
                    username=username,
                    email=email,
                    role_id=role_id,
                    status='active'
                )
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()

                AuditService.log(
                    action='USER_CREATE',
                    user_id=current_user.id,
                    entity_type='USER',
                    entity_id=str(new_user.id),
                    details=f"Created user account {username} ({email})"
                )
                flash(f"User account '{username}' created successfully.", "success")

        elif action == 'toggle_status':
            user_id = request.form.get('user_id', type=int)
            target_user = db.session.get(User, user_id)
            if target_user and target_user.id != current_user.id:
                old_status = target_user.status
                target_user.status = 'disabled' if target_user.status == 'active' else 'active'
                db.session.commit()

                AuditService.log(
                    action='USER_UPDATE',
                    user_id=current_user.id,
                    entity_type='USER',
                    entity_id=str(target_user.id),
                    details=f"Changed status for {target_user.username} from {old_status} to {target_user.status}"
                )
                flash(f"User status updated to {target_user.status}.", "info")

        elif action == 'change_role':
            user_id = request.form.get('user_id', type=int)
            role_id = request.form.get('role_id', type=int)
            target_user = db.session.get(User, user_id)
            if target_user and role_id:
                target_user.role_id = role_id
                db.session.commit()

                AuditService.log(
                    action='USER_UPDATE',
                    user_id=current_user.id,
                    entity_type='USER',
                    entity_id=str(target_user.id),
                    details=f"Updated role for {target_user.username} to role_id {role_id}"
                )
                flash(f"User role updated for {target_user.username}.", "success")

        return redirect(url_for('admin.users'))

    all_users = User.query.order_by(User.id.asc()).all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=all_users, roles=roles)


@bp.route('/rules', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
def rules():
    if request.method == 'POST':
        rule_id = request.form.get('rule_id', '').strip()
        rule = db.session.get(DetectionRule, rule_id)
        if rule:
            enabled = request.form.get('enabled') == '1'
            threshold = request.form.get('threshold', type=int)
            window = request.form.get('window', type=int)
            severity = request.form.get('severity', '').strip().upper()

            rule.enabled = enabled
            if threshold is not None:
                rule.threshold = threshold
            if window is not None:
                rule.time_window_seconds = window
            if severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                rule.severity = severity
            rule.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            AuditService.log(
                action='RULE_UPDATE',
                user_id=current_user.id,
                entity_type='RULE',
                entity_id=rule.id,
                details=f"Updated detection rule {rule.id}: enabled={enabled}, threshold={threshold}, window={window}"
            )
            flash(f"Detection Rule {rule.id} updated.", "success")
        return redirect(url_for('admin.rules'))

    all_rules = DetectionRule.query.order_by(DetectionRule.id.asc()).all()
    return render_template('admin/rules.html', rules=all_rules)


@bp.route('/audit-logs')
@login_required
@role_required('ADMIN')
def audit_logs():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '').strip()
    q = request.args.get('q', '').strip()

    query = AuditLog.query

    if action_filter:
        query = query.filter_by(action=action_filter)

    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (AuditLog.details.ilike(search_filter)) |
            (AuditLog.ip_address.ilike(search_filter)) |
            (AuditLog.entity_id.ilike(search_filter))
        )

    logs_pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20, error_out=False)
    distinct_actions = [r[0] for r in db.session.query(AuditLog.action).distinct().all()]

    return render_template(
        'admin/audit_logs.html',
        logs_pagination=logs_pagination,
        distinct_actions=distinct_actions,
        selected_action=action_filter,
        q=q
    )


@bp.route('/settings', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
def settings():
    if request.method == 'POST':
        for key, value in request.form.items():
            if key != 'csrf_token':
                Setting.set_value(key, value.strip())

        AuditService.log(
            action='SETTINGS_UPDATE',
            user_id=current_user.id,
            details="Updated global system SOC settings"
        )
        flash("System SOC configuration updated.", "success")
        return redirect(url_for('admin.settings'))

    all_settings = Setting.query.all()
    return render_template('admin/settings.html', settings=all_settings)
