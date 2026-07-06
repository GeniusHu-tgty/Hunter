from pathlib import Path

from core.draft_generator import generate_submission_draft_from_burp


def test_generate_submission_draft_from_burp(tmp_path: Path):
    source = tmp_path / 'burp'
    evidence = tmp_path / 'evidence'
    reports = tmp_path / 'reports'
    source.mkdir()
    (source / 'request.txt').write_text('REQ', encoding='utf-8')
    (source / 'response.txt').write_text('RESP', encoding='utf-8')
    (source / 'screen.png').write_text('PNG', encoding='utf-8')

    result = generate_submission_draft_from_burp(
        str(source),
        'https://jwgl.gnnu.edu.cn',
        'idor',
        style='butian',
        destination_dir=str(evidence),
        reports_dir=str(reports),
        title='?????????????',
        business_impact='???????????????',
    )

    report_path = Path(result['report_path'])
    assert report_path.exists()
    text = report_path.read_text(encoding='utf-8')
    assert '????' in text
    assert '???????????????' in text
    assert 'Request file:' in text or '???' in text
