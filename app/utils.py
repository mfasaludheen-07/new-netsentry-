import os
import uuid
import hashlib
import ipaddress
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from app.extensions import db


def safe_storage_filename(original_filename: str) -> str:
    """
    Combines secure_filename with a random UUID to avoid collisions
    and prevent arbitrary file write / path traversal vulnerabilities.
    """
    clean_name = secure_filename(original_filename)
    name, ext = os.path.splitext(clean_name)
    ext = ext.lower()
    random_token = uuid.uuid4().hex[:16]
    return f"{random_token}{ext}"


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    """Computes SHA-256 hash of byte content."""
    return hashlib.sha256(data).hexdigest()


def format_bytes(num_bytes: int) -> str:
    """Converts raw byte count into human readable units."""
    if not num_bytes or num_bytes < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def classify_ip_address(ip_str: str) -> dict:
    """
    Classifies an IP address using standard Python ipaddress library.
    Correctly distinguishes private, public, loopback, multicast, link-local, and reserved.
    """
    ip_str = (ip_str or '').strip()
    result = {
        'ip': ip_str,
        'valid': False,
        'version': None,
        'category': 'Unknown',
        'is_private': False,
        'is_global': False,
        'is_loopback': False,
        'is_multicast': False,
        'is_link_local': False,
        'is_reserved': False,
        'description': 'Invalid IP string'
    }

    try:
        addr = ipaddress.ip_address(ip_str)
        result['valid'] = True
        result['version'] = addr.version
        result['is_private'] = addr.is_private
        result['is_global'] = addr.is_global
        result['is_loopback'] = addr.is_loopback
        result['is_multicast'] = addr.is_multicast
        result['is_link_local'] = addr.is_link_local
        result['is_reserved'] = addr.is_reserved

        # Detailed categorization
        if addr.is_loopback:
            result['category'] = 'Loopback'
            result['description'] = f'Loopback Interface ({ip_str})'
        elif addr.is_private:
            result['category'] = 'Private Internal'
            result['description'] = f'RFC 1918 Private Subnet ({ip_str})'
        elif addr.is_link_local:
            result['category'] = 'Link-Local'
            result['description'] = f'RFC 3927 Link-Local ({ip_str})'
        elif addr.is_multicast:
            result['category'] = 'Multicast'
            result['description'] = f'RFC 5771 Multicast ({ip_str})'
        elif addr.is_reserved:
            result['category'] = 'Reserved / Documentation'
            result['description'] = f'Reserved / Test Network ({ip_str})'
        else:
            result['category'] = 'Public Routable'
            result['description'] = f'Public Internet Host ({ip_str})'

    except ValueError:
        result['category'] = 'Invalid'
        result['description'] = 'Unparseable IP syntax'

    return result


def is_private_or_internal_ip(ip_str: str) -> bool:
    """Returns True if IP is private, loopback, or link-local."""
    classification = classify_ip_address(ip_str)
    return classification['is_private'] or classification['is_loopback'] or classification['is_link_local']


def generate_next_case_id() -> str:
    """Generates the next sequential Case ID: NET-YYYY-000001"""
    from app.models import Case
    year = datetime.now().year
    prefix = f"NET-{year}-"
    last_case = Case.query.filter(Case.id.like(f"{prefix}%")).order_by(Case.id.desc()).first()
    
    if last_case and last_case.id.startswith(prefix):
        try:
            current_num = int(last_case.id.replace(prefix, ''))
            next_num = current_num + 1
        except ValueError:
            next_num = 1
    else:
        # Fallback to total case count + 1
        total = Case.query.count()
        next_num = total + 1

    return f"NET-{year}-{next_num:06d}"


def generate_next_alert_id() -> str:
    """Generates the next sequential Alert ID: ALT-YYYY-000001"""
    from app.models import Alert
    year = datetime.now().year
    prefix = f"ALT-{year}-"
    last_alert = Alert.query.filter(Alert.id.like(f"{prefix}%")).order_by(Alert.id.desc()).first()

    if last_alert and last_alert.id.startswith(prefix):
        try:
            current_num = int(last_alert.id.replace(prefix, ''))
            next_num = current_num + 1
        except ValueError:
            next_num = 1
    else:
        total = Alert.query.count()
        next_num = total + 1

    return f"ALT-{year}-{next_num:06d}"
