from flask import jsonify, request
from flask_login import login_required
from app.api import bp
from app.services.graph_service import GraphService


@bp.route('/graph', methods=['GET'])
@login_required
def get_graph():
    case_id = request.args.get('case_id')
    data = GraphService.get_graph_data(case_id=case_id)
    return jsonify(data)
