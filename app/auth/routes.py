from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from app.extensions import db
from app.auth import bp
from app.auth.forms import LoginForm
from app.models import User
from app.services.audit_service import AuditService


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.username.data.strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        now = datetime.now(timezone.utc)

        if user:
            # Check temporary account lockout
            if user.locked_until:
                # Normalizing locked_until to timezone-aware if needed
                locked_until_dt = user.locked_until.replace(tzinfo=timezone.utc) if user.locked_until.tzinfo is None else user.locked_until
                if locked_until_dt > now:
                    remaining_mins = max(1, int((locked_until_dt - now).total_seconds() // 60) + 1)
                    AuditService.log(action='LOGIN_FAILURE', user_id=user.id, details=f"Login attempt on locked account {user.username}")
                    flash(f"Account is temporarily locked due to repeated failed logins. Please retry in {remaining_mins} minute(s).", "danger")
                    return render_template('login.html', form=form)
                else:
                    # Lockout expired; reset lock window
                    user.locked_until = None
                    user.failed_logins = 0
                    db.session.commit()

            if user.check_password(form.password.data):
                if user.status != 'active':
                    flash("This account is currently deactivated. Contact your NetSentry administrator.", "danger")
                    AuditService.log(action='LOGIN_FAILURE', user_id=user.id, details="Attempted login on deactivated account")
                    return render_template('login.html', form=form)

                # Reset lockout counter on success
                user.failed_logins = 0
                user.locked_until = None
                db.session.commit()

                login_user(user, remember=form.remember.data)
                AuditService.log(action='LOGIN_SUCCESS', user_id=user.id, details=f"User {user.username} authenticated successfully")
                flash(f"Welcome back, {user.username}. Threat hunting workspace loaded.", "success")

                next_page = request.args.get('next')
                if not next_page or urlsplit(next_page).netloc != '':
                    next_page = url_for('dashboard.index')
                return redirect(next_page)
            else:
                # Increment failed attempts
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= 5:
                    user.locked_until = now + timedelta(minutes=15)
                    db.session.commit()
                    AuditService.log(action='LOGIN_FAILURE', user_id=user.id, details=f"Account {user.username} locked after 5 failed attempts")
                    flash("Too many failed login attempts. Your account has been temporarily locked for 15 minutes.", "danger")
                else:
                    attempts_left = 5 - user.failed_logins
                    db.session.commit()
                    AuditService.log(action='LOGIN_FAILURE', user_id=user.id, details=f"Invalid password for {identifier} (attempt {user.failed_logins}/5)")
                    flash(f"Invalid username or password. {attempts_left} attempt(s) remaining before temporary lockout.", "danger")
                return render_template('login.html', form=form)
        else:
            AuditService.log(action='LOGIN_FAILURE', details=f"Invalid login attempt for non-existent user: {identifier}")
            flash("Invalid username or password.", "danger")

    return render_template('login.html', form=form)


@bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    user_id = current_user.id
    username = current_user.username
    logout_user()
    AuditService.log(action='LOGOUT', user_id=user_id, details=f"User {username} logged out")
    flash("You have been signed out from the NetSentry platform.", "info")
    return redirect(url_for('auth.login'))
