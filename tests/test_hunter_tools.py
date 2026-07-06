"""
Hunter Tool Tests - Verify all auto_* tools work standalone.
Run: python -m pytest tests/test_hunter_tools.py -v
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fix Windows encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


def test_auto_sqli_import():
    """Test auto_sqli imports successfully."""
    from core.auto_sqli import AutoSQLi
    assert AutoSQLi is not None


def test_auto_xss_import():
    """Test auto_xss imports successfully."""
    from core.auto_xss import AutoXSS
    assert AutoXSS is not None


def test_auto_ssti_import():
    """Test auto_ssti imports successfully."""
    from core.auto_ssti import AutoSSTI
    assert AutoSSTI is not None


def test_auto_ssrf_import():
    """Test auto_ssrf imports successfully."""
    from core.auto_ssrf import AutoSSRF
    assert AutoSSRF is not None


def test_auto_xxe_import():
    """Test auto_xxe imports successfully."""
    from core.auto_xxe import AutoXXE
    assert AutoXXE is not None


def test_auto_cmd_import():
    """Test auto_cmd imports successfully."""
    from core.auto_cmd import AutoCMD
    assert AutoCMD is not None


def test_auto_idor_import():
    """Test auto_idor imports successfully."""
    from core.auto_idor import AutoIDOR
    assert AutoIDOR is not None


def test_jwt_tool_import():
    """Test jwt_tool imports successfully."""
    from core.jwt_tool import JWTTool
    assert JWTTool is not None


def test_probe_import():
    """Test probe imports successfully."""
    from core.probe import probe_impl
    assert probe_impl is not None


def test_src_read_import():
    """Test src_read imports successfully."""
    from core.src_read import src_read_impl
    assert src_read_impl is not None


def test_inject_import():
    """Test inject imports successfully."""
    from core.inject import inject_impl
    assert inject_impl is not None


def test_burp_bridge_import():
    """Test burp_bridge imports successfully."""
    from core.burp_bridge import BurpBridge
    assert BurpBridge is not None


if __name__ == '__main__':
    tests = [
        test_auto_sqli_import,
        test_auto_xss_import,
        test_auto_ssti_import,
        test_auto_ssrf_import,
        test_auto_xxe_import,
        test_auto_cmd_import,
        test_auto_idor_import,
        test_jwt_tool_import,
        test_probe_import,
        test_src_read_import,
        test_inject_import,
        test_burp_bridge_import,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f'✅ {test.__name__}')
            passed += 1
        except Exception as e:
            print(f'❌ {test.__name__}: {e}')
            failed += 1

    print(f'\n{passed}/{passed + failed} tests passed')
