from functools import wraps
from flask import abort, flash, redirect, url_for, request
from flask_login import current_user

def role_required(*allowed_roles):
    """
    Decorator to restrict route access by role.
    Usage:
        @role_required('ADMIN')
        @role_required('ADMIN', 'ANALYST')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login', next=request.url))

            user_role = current_user.role.name.upper() if current_user.role else 'VIEWER'
            allowed = [r.upper() for r in allowed_roles]

            if user_role not in allowed:
                # If it's an API request, return JSON 403 or abort
                if request.is_json or request.path.startswith('/api/'):
                    abort(403)
                flash(f"Access Denied: You need {' or '.join(allowed)} privileges for this action.", 'danger')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Convenience decorator for admin-only actions."""
    return role_required('ADMIN')(f)


def analyst_required(f):
    """Convenience decorator for analyst or admin actions."""
    return role_required('ADMIN', 'ANALYST')(f)
