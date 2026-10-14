import unittest
from datetime import datetime
from app.services.normalizer import EventNormalizer


class TestNormalizer(unittest.TestCase):
    """Test normalization of diverse telemetry headers and formats."""

    def test_canonical_fields_extraction(self):
        raw = {
            'source_ip': '192.168.1.50',
            'destination_ip': '10.0.0.1',
            'source_port': '49152',
            'destination_port': '443',
            'protocol': 'tcp',
            'hostname': 'WS-FIN-01',
            'username': 'bob.ross',
            'bytes_sent': '1500',
            'bytes_received': '4200',
            'timestamp': '2026-10-06 12:00:00',
            'event_type': 'connection',
            'action': 'ALLOW'
        }
        normalized = EventNormalizer.normalize(raw, source_type='test')
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized['source_ip'], '192.168.1.50')
        self.assertEqual(normalized['destination_ip'], '10.0.0.1')
        self.assertEqual(normalized['source_port'], 49152)
        self.assertEqual(normalized['destination_port'], 443)
        self.assertEqual(normalized['protocol'], 'TCP')
        self.assertEqual(normalized['hostname'], 'WS-FIN-01')
        self.assertEqual(normalized['username'], 'bob.ross')
        self.assertEqual(normalized['bytes_sent'], 1500)
        self.assertEqual(normalized['bytes_received'], 4200)

    def test_header_alias_mapping(self):
        raw = {
            'client_ip': '192.168.1.75',
            'server_ip': '203.0.113.5',
            'sport': '55231',
            'dport': '80',
            'proto': 'udp',
            'device_name': 'CORP-LAPTOP',
            'out_bytes': '800',
            'in_bytes': '1200',
            'date': '2026-10-06T14:30:00Z',
            'sni': 'api.threat.test'
        }
        normalized = EventNormalizer.normalize(raw)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized['source_ip'], '192.168.1.75')
        self.assertEqual(normalized['destination_ip'], '203.0.113.5')
        self.assertEqual(normalized['source_port'], 55231)
        self.assertEqual(normalized['destination_port'], 80)
        self.assertEqual(normalized['protocol'], 'UDP')
        self.assertEqual(normalized['hostname'], 'CORP-LAPTOP')
        self.assertEqual(normalized['domain'], 'api.threat.test')
        self.assertEqual(normalized['bytes_sent'], 800)
        self.assertEqual(normalized['bytes_received'], 1200)

    def test_invalid_ip_rejection(self):
        raw = {
            'source_ip': 'invalid_ip_address',
            'destination_ip': '10.0.0.1',
            'destination_port': 80
        }
        normalized = EventNormalizer.normalize(raw)
        self.assertIsNone(normalized)

    def test_invalid_port_handling(self):
        raw = {
            'source_ip': '192.168.1.1',
            'destination_ip': '10.0.0.1',
            'destination_port': '9999999',  # Invalid port
            'protocol': 'tcp'
        }
        normalized = EventNormalizer.normalize(raw)
        self.assertIsNotNone(normalized)
        self.assertIsNone(normalized['destination_port'])

    def test_raw_event_preserved(self):
        raw = {
            'source_ip': '192.168.1.1',
            'destination_ip': '10.0.0.1',
            'custom_soc_flag': 'RED_ALERT'
        }
        normalized = EventNormalizer.normalize(raw)
        self.assertIsNotNone(normalized)
        self.assertIn('raw_event', normalized)
        self.assertIn('RED_ALERT', normalized['raw_event'])


if __name__ == '__main__':
    unittest.main()
