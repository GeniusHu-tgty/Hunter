"""
Hunter Tool Tests - Verify all core/* tools work standalone.
Run: cd /path/to/hunter && python tests/test_hunter_tools.py
"""

import sys
import os
import io

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def import_tool(module_path, class_name):
    """Generic import test."""
    mod = __import__(module_path, fromlist=[class_name])
    cls = getattr(mod, class_name)
    assert cls is not None
    return cls


def test_auto_sqli():
    assert import_tool('core.auto_sqli', 'AutoSQLi') is not None

def test_auto_xss():
    assert import_tool('core.auto_xss', 'AutoXSS') is not None

def test_auto_ssti():
    assert import_tool('core.auto_ssti', 'AutoSSTI') is not None

def test_auto_ssrf():
    assert import_tool('core.auto_ssrf', 'AutoSSRF') is not None

def test_auto_xxe():
    assert import_tool('core.auto_xxe', 'AutoXXE') is not None

def test_auto_cmd():
    assert import_tool('core.auto_cmd', 'AutoCMD') is not None

def test_auto_idor():
    assert import_tool('core.auto_idor', 'AutoIDOR') is not None


if __name__ == '__main__':
    # Fix Windows encoding only for direct script execution.
    # Rewrapping stdout/stderr at import time breaks pytest capture.
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

    tests = [
        test_auto_sqli,
        test_auto_xss,
        test_auto_ssti,
        test_auto_ssrf,
        test_auto_xxe,
        test_auto_cmd,
        test_auto_idor,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f'PASS {test.__name__}')
            passed += 1
        except Exception as e:
            print(f'FAIL {test.__name__}: {e}')
            failed += 1

    print(f'\n{passed}/{passed + failed} tests passed')
