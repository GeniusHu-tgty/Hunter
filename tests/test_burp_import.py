from pathlib import Path

from core.burp_import import import_burp_evidence


def test_import_burp_evidence(tmp_path: Path):
    source = tmp_path / 'burp'
    dest = tmp_path / 'hunter'
    source.mkdir()
    (source / 'request.txt').write_text('REQ', encoding='utf-8')
    (source / 'response.txt').write_text('RESP', encoding='utf-8')
    (source / 'screen.png').write_text('PNG', encoding='utf-8')
    (source / 'result.json').write_text('{}', encoding='utf-8')

    result = import_burp_evidence(str(source), 'https://jwgl.gnnu.edu.cn', 'idor', str(dest))

    assert result['prefix'].endswith('_idor')
    assert Path(result['request_file']).exists()
    assert Path(result['response_file']).exists()
    assert any(Path(path).exists() for path in result['screenshot_files'])
    assert any(Path(path).exists() for path in result['evidence_files'])

def test_quick_burp_import_script_exists():
    script = Path(r"C:\Users\Administrator\.agents\skills\hunter\core\scripts\quick_burp_import.ps1")
    assert script.exists()


import asyncio
import json
import sys


def test_hunter_burp_import_mcp_like_flow(tmp_path: Path):
    sys.path.insert(0, r"C:\Users\Administrator\.agents\skills\hunter")
    import mcp_server

    source = tmp_path / "burp2"
    dest = tmp_path / "hunter2"
    source.mkdir()
    (source / "request.txt").write_text("REQ", encoding="utf-8")
    (source / "response.txt").write_text("RESP", encoding="utf-8")

    result = asyncio.run(mcp_server.hunter_burp_import(str(source), "https://jwgl.gnnu.edu.cn", "idor", str(dest)))
    data = json.loads(result)
    assert data["prefix"].endswith("_idor")
    assert Path(data["request_file"]).exists()
    assert Path(data["response_file"]).exists()
