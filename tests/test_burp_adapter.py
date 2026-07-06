from pathlib import Path

from core.burp_adapter import classify_burp_exports, suggest_hunter_prefix


def test_suggest_hunter_prefix():
    assert suggest_hunter_prefix('https://jwgl.gnnu.edu.cn', 'idor') == 'https___jwgl_gnnu_edu_cn_idor'.strip('_') or suggest_hunter_prefix('https://jwgl.gnnu.edu.cn', 'idor').endswith('_idor')


def test_classify_burp_exports(tmp_path: Path):
    files = [
        tmp_path / 'gnnu_idor_request.txt',
        tmp_path / 'gnnu_idor_response.txt',
        tmp_path / 'gnnu_idor_screenshot.png',
        tmp_path / 'gnnu_idor_result.json',
    ]
    for file in files:
        file.write_text('x', encoding='utf-8')

    result = classify_burp_exports(str(tmp_path), 'gnnu_idor')
    assert result['request_file'].endswith('request.txt')
    assert result['response_file'].endswith('response.txt')
    assert any(path.endswith('screenshot.png') for path in result['screenshot_files'])
    assert any(path.endswith('result.json') for path in result['evidence_files'])
