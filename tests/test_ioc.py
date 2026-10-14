from tests.base_test import BaseTestCase
from app.utils import classify_ip_address, is_private_or_internal_ip
from app.services.ioc_service import IOCService
from app.models import IOC
from app.extensions import db


class TestIOCClassification(BaseTestCase):
    """Test RFC-compliant IP address categorization and IOC tracking."""

    def test_rfc_ip_classification(self):
        # 1. RFC 1918 Private IPv4
        info_priv = classify_ip_address('192.168.1.10')
        self.assertTrue(info_priv['valid'])
        self.assertTrue(info_priv['is_private'])
        self.assertEqual(info_priv['version'], 4)
        self.assertTrue(is_private_or_internal_ip('192.168.1.10'))
        self.assertTrue(is_private_or_internal_ip('10.0.0.5'))
        self.assertTrue(is_private_or_internal_ip('172.16.0.1'))

        # 2. Loopback IPv4 & IPv6
        info_loop = classify_ip_address('127.0.0.1')
        self.assertTrue(info_loop['is_loopback'])
        info_loop6 = classify_ip_address('::1')
        self.assertTrue(info_loop6['is_loopback'])
        self.assertEqual(info_loop6['version'], 6)

        # 3. Multicast
        info_multi = classify_ip_address('224.0.0.1')
        self.assertTrue(info_multi['is_multicast'])

        # 4. Link-local
        info_link = classify_ip_address('169.254.1.1')
        self.assertTrue(info_link['is_link_local'])

        # 5. Public / Global IP
        info_pub = classify_ip_address('8.8.8.8')
        self.assertTrue(info_pub['is_global'])
        self.assertFalse(info_pub['is_private'])
        self.assertFalse(is_private_or_internal_ip('8.8.8.8'))

        # 6. Invalid IP
        info_inv = classify_ip_address('not_an_ip')
        self.assertFalse(info_inv['valid'])

    def test_ioc_observation_lifecycle(self):
        # Observe domain IOC
        ioc_id = IOCService.observe_ioc('suspicious.example', 'DOMAIN')
        self.assertGreater(ioc_id, 0)

        ioc = db.session.get(IOC, ioc_id)
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc.value, 'suspicious.example')
        self.assertEqual(ioc.type, 'DOMAIN')
        # Crucial requirement: Do not automatically label an IOC malicious
        self.assertEqual(ioc.status, 'OBSERVED')
        self.assertEqual(ioc.confidence, 'LOW')

        # Analyst updates IOC status to SUSPICIOUS
        ioc.status = 'SUSPICIOUS'
        ioc.confidence = 'HIGH'
        db.session.commit()

        updated_ioc = db.session.get(IOC, ioc_id)
        self.assertEqual(updated_ioc.status, 'SUSPICIOUS')
        self.assertEqual(updated_ioc.confidence, 'HIGH')
