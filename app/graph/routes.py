from flask import render_template, request, jsonify
from flask_login import login_required
from app.graph import bp
from app.models import Case
from app.services.graph_service import GraphService


@bp.route('/graph')
@login_required
def index():
    case_id = request.args.get('case_id', '').strip()
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template('graph/index.html', cases=cases, selected_case_id=case_id)


@bp.route('/graph/data')
@login_required
def data():
    case_id = request.args.get('case_id', '').strip()
    graph_json = GraphService.get_graph_data(case_id=case_id or None)
    return jsonify(graph_json)
