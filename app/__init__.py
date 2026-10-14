import os
from flask import Flask, render_template, jsonify, request
from config import config
from app.extensions import db, login_manager, csrf
from app.utils import format_bytes, is_private_or_internal_ip


def create_app(config_name: str = 'default') -> Flask:
    """
    Application factory for NetSentry Threat Hunting Platform.
    """
    app = Flask(__name__)
    
    # Load configuration
    cfg = config.get(config_name, config['default'])
    app.config.from_object(cfg)
    if hasattr(cfg, 'init_app'):
        cfg.init_app(app)

    # Ensure required storage folders exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['EVIDENCE_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOGS_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Exclude API endpoints from standard CSRF form check if JSON/token used, or handle dynamically
    # Flask-WTF CSRFProtect validates headers 'X-CSRFToken' and 'X-CSRF-Token' automatically!

    # Register Blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from app.dashboard import bp as dashboard_bp
    app.register_blueprint(dashboard_bp)

    from app.logs import bp as logs_bp
    app.register_blueprint(logs_bp)

    from app.alerts import bp as alerts_bp
    app.register_blueprint(alerts_bp)

    from app.cases import bp as cases_bp
    app.register_blueprint(cases_bp)

    from app.iocs import bp as iocs_bp
    app.register_blueprint(iocs_bp)

    from app.endpoints import bp as endpoints_bp
    app.register_blueprint(endpoints_bp)

    from app.timeline import bp as timeline_bp
    app.register_blueprint(timeline_bp)

    from app.graph import bp as graph_bp
    app.register_blueprint(graph_bp)

    from app.evidence import bp as evidence_bp
    app.register_blueprint(evidence_bp)

    from app.reports import bp as reports_bp
    app.register_blueprint(reports_bp)

    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    from app.api import bp as api_bp
    app.register_blueprint(api_bp)

    # Register Jinja context processors & filters
    @app.context_processor
    def inject_global_template_vars():
        from app.models import Alert
        unread_alerts_count = 0
        try:
            unread_alerts_count = Alert.query.filter(Alert.status.in_(['NEW', 'TRIAGED'])).count()
        except Exception:
            pass

        return {
            'app_name': 'NetSentry',
            'app_subtitle': 'Threat Hunting & Attack Reconstruction Platform',
            'unread_alerts_count': unread_alerts_count
        }

    @app.template_filter('filesizeformat')
    def filter_filesizeformat(num_bytes):
        return format_bytes(num_bytes)

    @app.template_filter('is_private_ip')
    def filter_is_private_ip(ip_str):
        return is_private_or_internal_ip(ip_str)

    # Register Error Handlers
    @app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template('errors/500.html'), 500

    # Register Security Headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        
        # Content Security Policy allowing required styles, fonts, and scripts for SOC dashboard
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:",
            "img-src 'self' data: https:",
            "connect-src 'self'",
            "frame-ancestors 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)

        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response

    return app
