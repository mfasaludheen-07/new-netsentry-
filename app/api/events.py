from flask import jsonify, request
from flask_login import login_required
from app.api import bp
from app.models import NetworkEvent


@bp.route('/events', methods=['GET'])
@login_required
def get_events():
    raw_limit = request.args.get('limit', 50, type=int)
    limit = max(1, min(raw_limit or 50, 200))
    src_ip = request.args.get('source_ip')
    dst_ip = request.args.get('destination_ip')
    hostname = request.args.get('hostname')

    query = NetworkEvent.query
    if src_ip:
        query = query.filter_by(source_ip=src_ip)
    if dst_ip:
        query = query.filter_by(destination_ip=dst_ip)
    if hostname:
        query = query.filter_by(hostname=hostname)

    events = query.order_by(NetworkEvent.timestamp.desc()).limit(limit).all()

    return jsonify({
        'count': len(events),
        'events': [
            {
                'id': e.id,
                'timestamp': str(e.timestamp),
                'source_ip': e.source_ip,
                'destination_ip': e.destination_ip,
                'source_port': e.source_port,
                'destination_port': e.destination_port,
                'protocol': e.protocol,
                'hostname': e.hostname,
                'username': e.username,
                'domain': e.domain,
                'bytes_sent': e.bytes_sent,
                'bytes_received': e.bytes_received,
                'action': e.action,
                'event_type': e.event_type
            } for e in events
        ]
    })
