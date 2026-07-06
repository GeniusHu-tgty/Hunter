"""
Hunter Tool Tests - Verify all core/* tools work standalone.
Run: cd /path/to/hunter && python tests/test_hunter_tools.py
"""

import sys
import os
import io

# Fix Windows encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_import(module_path, class_name):
    """Generic import test."""
    mod = __import__(module_path, fromlist=[class_name])
    cls = getattr(mod, class_name)
    assert cls is not None
    return cls


def test_auto_sqli():
    return test_import('core.auto_sqli', 'AutoSQLi')

def test_auto_xss():
    return test_import('core.auto_xss', 'AutoXSS')

def test_auto_ssti():
    return test_import('core.auto_ssti', 'AutoSSTI')

def test_auto_ssrf():
    return test_import('core.auto_ssrf', 'AutoSSRF')

def test_auto_xxe():
    return test_import('core.auto_xxe', 'AutoXXE')

def test_auto_cmd():
    return test_import('core.auto_cmd', 'AutoCMD')

def test_auto_idor():
    return test_import('core.auto_idor', 'AutoIDOR')


if __name__ == '__main__':
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
