import json
from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.extensions import db
from app.reports import bp
from app.models import Report, Case
from app.decorators import role_required
from app.services.report_service import ReportService


@bp.route('/reports', strict_slashes=False)
@bp.route('/reports/', strict_slashes=False)
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    reports_pagination = Report.query.order_by(Report.generated_at.desc()).paginate(page=page, per_page=15, error_out=False)
    cases = Case.query.all()
    return render_template('reports/index.html', reports_pagination=reports_pagination, cases=cases)


@bp.route('/reports/generate/<case_id>', methods=['POST'])
@login_required
@role_required('ADMIN', 'ANALYST')
def generate(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        abort(404)

    title = request.form.get('title', f"Forensic Investigation Report - {case.id}").strip()
    summary = request.form.get('summary', '').strip()

    try:
        report_id = ReportService.save_report(
            case_id=case.id,
            title=title,
            summary=summary or None,
            user_id=current_user.id
        )
        flash(f"Formal forensic investigation report generated for case {case.id}.", "success")
        return redirect(url_for('reports.view', report_id=report_id))
    except Exception as e:
        flash(f"Failed to generate report: {e}", "danger")
        return redirect(url_for('cases.view', case_id=case.id, tab='report'))


@bp.route('/reports/<int:report_id>')
@login_required
def view(report_id):
    report = db.session.get(Report, report_id)
    if not report:
        abort(404)

    data = {}
    if report.report_data:
        try:
            data = json.loads(report.report_data)
        except Exception:
            pass

    return render_template('reports/view.html', report=report, data=data)


@bp.route('/reports/<int:report_id>/print')
@login_required
def print_report(report_id):
    report = db.session.get(Report, report_id)
    if not report:
        abort(404)

    data = {}
    if report.report_data:
        try:
            data = json.loads(report.report_data)
        except Exception:
            pass

    return render_template('reports/print.html', report=report, data=data)
