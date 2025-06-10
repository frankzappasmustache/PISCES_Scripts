import os
import sys
import types
import pytest

# Ensure the repository root is on the import path when tests are run from
# within the ``tests`` directory.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The module under test imports optional dependencies like ``requests`` and
# ``openpyxl``. Provide lightweight stubs so the import succeeds without the
# real packages being installed.
requests_stub = types.ModuleType('requests')
class DummySession:
    def __init__(self):
        self.headers = {}
        self.auth = None
requests_stub.Session = DummySession
sys.modules['requests'] = requests_stub
openpyxl_stub = types.ModuleType('openpyxl')
styles_stub = types.ModuleType('styles')
class Font: pass
class PatternFill: pass
styles_stub.Font = Font
styles_stub.PatternFill = PatternFill
openpyxl_stub.styles = styles_stub
sys.modules['openpyxl'] = openpyxl_stub
sys.modules['openpyxl.styles'] = styles_stub

import ip_reputation_virus_total_empty as ip_utils


def test_is_public_ip_valid_public():
    assert ip_utils.is_public_ip('8.8.8.8')
    assert ip_utils.is_public_ip('1.1.1.1')


def test_is_public_ip_private_addresses():
    for ip in ['10.0.0.1', '192.168.1.5', '172.16.0.1']:
        assert not ip_utils.is_public_ip(ip)


def test_is_public_ip_invalid_string():
    assert not ip_utils.is_public_ip('not an ip')


def test_extract_ips_filters_private():
    hits = [
        {'_source': {'source': {'ip': '8.8.8.8'}, 'destination': {'ip': '10.0.0.1'}}},
        {'_source': {'source': {'ip': '192.168.0.2'}, 'destination': {'ip': '1.1.1.1'}}}
    ]
    result = ip_utils.extract_ips(hits)
    # Should include only public IPs
    assert result == sorted(['8.8.8.8', '1.1.1.1'])


def test_extract_ips_respects_per_run_limit(monkeypatch):
    # Patch limit to a smaller number for testing
    monkeypatch.setattr(ip_utils, 'PER_RUN_LIMIT', 5)
    hits = []
    for i in range(10):
        ip = f'8.8.8.{i}'
        hits.append({'_source': {'source': {'ip': ip}, 'destination': {'ip': None}}})
    result = ip_utils.extract_ips(hits)
    assert len(result) == 5
    assert result == sorted([f'8.8.8.{i}' for i in range(5)])
