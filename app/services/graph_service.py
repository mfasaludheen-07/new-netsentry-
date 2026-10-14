from app.extensions import db
from app.models import NetworkEvent, Alert, Case, CaseEvent, CaseAlert
from app.services.ioc_service import IOCService


class GraphService:
    @classmethod
    def get_graph_data(cls, case_id: str = None) -> dict:
        """
        Builds a Cytoscape.js compatible graph dataset of endpoints, IPs, domains, and cases.
        """
        nodes = {}
        edges = {}

        def add_node(node_id: str, label: str, node_type: str, meta: dict = None):
            meta = meta or {}
            if node_id not in nodes:
                color = '#94a3b8'
                shape = 'ellipse'
                icon = 'fa-circle'

                if node_type == 'endpoint':
                    color = '#38bdf8'  # sky blue
                    shape = 'rectangle'
                    icon = 'fa-desktop'
                elif node_type == 'internal_ip':
                    color = '#34d399'  # emerald
                    shape = 'round-rectangle'
                    icon = 'fa-server'
                elif node_type == 'external_ip':
                    color = '#f87171'  # red
                    shape = 'hexagon'
                    icon = 'fa-globe'
                elif node_type == 'domain':
                    color = '#fbbf24'  # amber
                    shape = 'diamond'
                    icon = 'fa-link'
                elif node_type == 'case':
                    color = '#a855f7'  # purple
                    shape = 'octagon'
                    icon = 'fa-folder-open'

                data = {
                    'id': node_id,
                    'label': label,
                    'type': node_type,
                    'color': color,
                    'shape': shape,
                    'icon': icon,
                    'event_count': meta.get('event_count', 0),
                    'alert_count': meta.get('alert_count', 0),
                    'first_seen': str(meta.get('first_seen')) if meta.get('first_seen') else None,
                    'last_seen': str(meta.get('last_seen')) if meta.get('last_seen') else None
                }
                data.update({k: v for k, v in meta.items() if k not in data})
                nodes[node_id] = {'data': data}
            else:
                existing_data = nodes[node_id]['data']
                if meta.get('event_count'):
                    existing_data['event_count'] += meta['event_count']
                if meta.get('alert_count'):
                    existing_data['alert_count'] += meta['alert_count']
                if meta.get('last_seen'):
                    existing_data['last_seen'] = str(meta['last_seen'])

        def add_edge(source: str, target: str, label: str, edge_type: str, meta: dict = None):
            meta = meta or {}
            edge_id = f"e_{source}_{target}_{edge_type}"
            if edge_id not in edges:
                color = '#64748b'
                if edge_type == 'COMMUNICATED_WITH':
                    color = '#f87171'
                elif edge_type == 'RESOLVED_TO':
                    color = '#fbbf24'
                elif edge_type == 'CONNECTED_TO':
                    color = '#22d3ee'
                elif edge_type == 'OBSERVED_IN':
                    color = '#c084fc'

                data = {
                    'id': edge_id,
                    'source': source,
                    'target': target,
                    'label': label,
                    'type': edge_type,
                    'color': color,
                    'weight': 1
                }
                data.update({k: v for k, v in meta.items() if k not in data})
                edges[edge_id] = {'data': data}
            else:
                edges[edge_id]['data']['weight'] += 1

        # 1. If scoped to case, add Case Node
        if case_id:
            c = db.session.get(Case, case_id)
            if c:
                add_node(f"case_{c.id}", c.id, 'case', {
                    'title': c.title,
                    'severity': c.severity,
                    'status': c.status,
                    'first_seen': c.created_at,
                    'last_seen': c.updated_at
                })

        # 2. Query network events
        if case_id:
            events = db.session.query(NetworkEvent).join(
                CaseEvent, NetworkEvent.id == CaseEvent.event_id
            ).filter(CaseEvent.case_id == case_id).all()
        else:
            events = NetworkEvent.query.order_by(NetworkEvent.id.desc()).limit(200).all()

        for ev in events:
            src_ip = ev.source_ip
            dst_ip = ev.destination_ip
            hostname = ev.hostname
            domain = ev.domain
            proto = ev.protocol or 'TCP'
            ts = ev.timestamp

            src_type = 'internal_ip' if IOCService.is_private_ip(src_ip) else 'external_ip'
            src_node_id = f"ip_{src_ip}"
            add_node(src_node_id, src_ip, src_type, {
                'first_seen': ts,
                'last_seen': ts,
                'event_count': 1
            })

            if hostname:
                ep_node_id = f"ep_{hostname}"
                add_node(ep_node_id, hostname, 'endpoint', {
                    'ip_address': src_ip,
                    'first_seen': ts,
                    'last_seen': ts,
                    'event_count': 1
                })
                add_edge(ep_node_id, src_node_id, 'Configured IP', 'CONNECTED_TO')
                if case_id:
                    add_edge(ep_node_id, f"case_{case_id}", 'Observed In', 'OBSERVED_IN')

            dst_type = 'internal_ip' if IOCService.is_private_ip(dst_ip) else 'external_ip'
            dst_node_id = f"ip_{dst_ip}"
            add_node(dst_node_id, dst_ip, dst_type, {
                'first_seen': ts,
                'last_seen': ts,
                'event_count': 1
            })

            edge_label = f"{proto}:{ev.destination_port}" if ev.destination_port else proto
            add_edge(src_node_id, dst_node_id, edge_label, 'COMMUNICATED_WITH', {
                'protocol': proto,
                'port': ev.destination_port,
                'bytes': (ev.bytes_sent or 0) + (ev.bytes_received or 0)
            })

            if domain:
                dom_node_id = f"dom_{domain}"
                add_node(dom_node_id, domain, 'domain', {
                    'first_seen': ts,
                    'last_seen': ts,
                    'event_count': 1
                })
                add_edge(dom_node_id, dst_node_id, 'Resolves To', 'RESOLVED_TO')
                if hostname:
                    add_edge(f"ep_{hostname}", dom_node_id, 'Queried', 'CONNECTED_TO')

        # 3. Associate alert counts
        if case_id:
            alerts = db.session.query(Alert).join(
                CaseAlert, Alert.id == CaseAlert.alert_id
            ).filter(CaseAlert.case_id == case_id).all()
        else:
            alerts = Alert.query.limit(100).all()

        for al in alerts:
            src_key = f"ip_{al.source_ip}"
            if src_key in nodes:
                nodes[src_key]['data']['alert_count'] += 1
            if al.endpoint:
                ep_key = f"ep_{al.endpoint}"
                if ep_key in nodes:
                    nodes[ep_key]['data']['alert_count'] += 1

        return {
            'nodes': list(nodes.values()),
            'edges': list(edges.values())
        }
