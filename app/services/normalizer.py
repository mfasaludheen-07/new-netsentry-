import json
import ipaddress
from datetime import datetime, timezone


class EventNormalizer:
    """
    Normalizes diverse network telemetry inputs into NetSentry's canonical schema.
    """

    @classmethod
    def normalize(cls, raw_row: dict, source_type: str = 'generic', default_timezone: str = 'UTC') -> dict | None:
        """
        Takes raw dictionary row, maps aliases, validates network fields,
        and returns canonical dict or None if row is invalid.
        """
        if not raw_row or not isinstance(raw_row, dict):
            return None

        # Clean string keys and values
        row = {}
        for k, v in raw_row.items():
            k_clean = str(k).strip().lower()
            if isinstance(v, str):
                v_clean = v.strip()
            else:
                v_clean = v
            row[k_clean] = v_clean

        # 1. Source IP
        src_ip = cls._extract_field(row, [
            'source_ip', 'src_ip', 'src', 'source', 'client_ip', 'sourceaddress', 'srcip', 'c-ip', 'id.orig_h'
        ])
        if not src_ip or not cls._is_valid_ip(src_ip):
            return None

        # 2. Destination IP
        dst_ip = cls._extract_field(row, [
            'destination_ip', 'dst_ip', 'dst', 'destination', 'server_ip', 'dest_ip', 'destinationaddress', 'dstip', 's-ip', 'id.resp_h'
        ])
        if not dst_ip or not cls._is_valid_ip(dst_ip):
            return None

        # 3. Source Port
        src_port = cls._extract_field(row, ['source_port', 'src_port', 'sport', 'sourceport', 'id.orig_p'])
        src_port = cls._parse_port(src_port)

        # 4. Destination Port
        dst_port = cls._extract_field(row, ['destination_port', 'dst_port', 'dest_port', 'dport', 'destinationport', 'id.resp_p'])
        dst_port = cls._parse_port(dst_port)

        # 5. Timestamp Normalization
        ts_val = cls._extract_field(row, ['timestamp', 'time', 'datetime', 'date', 'ts', '@timestamp', 'event_time'])
        normalized_time = cls._parse_timestamp(ts_val)

        # 6. Protocol
        protocol = str(cls._extract_field(row, ['protocol', 'proto', 'transport_protocol', 'proto_name']) or 'TCP').upper()

        # 7. Hostname / Endpoint
        hostname = cls._extract_field(row, ['hostname', 'host', 'computer_name', 'endpoint', 'device_name', 'host_name'])

        # 8. Username
        username = cls._extract_field(row, ['username', 'user', 'user_name', 'account', 'src_user'])

        # 9. Domain / DNS query
        dns_query = cls._extract_field(row, ['dns_query', 'query', 'dns', 'query_name', 'qname'])
        domain = cls._extract_field(row, ['domain', 'destination_domain', 'target_domain', 'sni', 'host_header'])
        if not domain and dns_query:
            domain = dns_query

        # 10. Bytes
        bytes_sent = cls._parse_int(cls._extract_field(row, ['bytes_sent', 'bytes_out', 'orig_bytes', 'bytes', 'sent_bytes', 'out_bytes']), default=0)
        bytes_received = cls._parse_int(cls._extract_field(row, ['bytes_received', 'bytes_in', 'resp_bytes', 'recv_bytes', 'in_bytes']), default=0)

        # 11. Event Type
        event_type = cls._extract_field(row, ['event_type', 'type', 'category', 'action_type'])
        if not event_type:
            if dns_query or (dst_port == 53):
                event_type = 'dns_query'
            elif dst_port in (445, 139):
                event_type = 'smb_connection'
            elif dst_port in (22, 3389):
                event_type = 'remote_access'
            else:
                event_type = 'connection'

        # 12. Action (ALLOW / DENY)
        raw_action = str(cls._extract_field(row, ['action', 'act', 'verdict', 'status', 'rule_action']) or 'ALLOW').upper()
        if raw_action in ('BLOCK', 'DENIED', 'DENY', 'DROP', 'REJECT', 'RESET'):
            action = 'DENY'
        elif raw_action in ('PERMIT', 'ACCEPTED', 'ALLOWED', 'ALLOW', 'PASS', 'SUCCESS', 'RESOLVED'):
            action = 'ALLOW'
        else:
            action = raw_action

        return {
            'timestamp': normalized_time,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': protocol,
            'hostname': hostname,
            'username': username,
            'domain': domain,
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received,
            'dns_query': dns_query,
            'event_type': event_type,
            'action': action,
            'source_type': source_type,
            'raw_event': json.dumps(raw_row, default=str)
        }

    @staticmethod
    def _extract_field(row: dict, candidates: list):
        for c in candidates:
            if c in row and row[c] not in (None, '', '-'):
                return row[c]
        return None

    @staticmethod
    def _is_valid_ip(val) -> bool:
        try:
            ipaddress.ip_address(str(val).strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _parse_port(val) -> int | None:
        if val is None or val == '' or val == '-':
            return None
        try:
            port = int(val)
            if 0 <= port <= 65535:
                return port
        except (ValueError, TypeError):
            pass
        return None

    @staticmethod
    def _parse_int(val, default=0) -> int:
        if val is None or val == '':
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _parse_timestamp(val) -> datetime:
        if not val:
            return datetime.now()

        # Numeric unix timestamp
        try:
            ts_float = float(val)
            return datetime.fromtimestamp(ts_float)
        except (ValueError, TypeError):
            pass

        # Formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S%z',
            '%d/%b/%Y:%H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%Y-%m-%d'
        ]

        cleaned_str = str(val).strip().replace('Z', '')
        for fmt in formats:
            try:
                return datetime.strptime(cleaned_str, fmt)
            except ValueError:
                continue

        # Fallback to current time
        return datetime.now()
