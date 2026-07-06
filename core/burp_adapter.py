from pathlib import Path
from typing import Dict, List


def _normalize_name(name: str) -> str:
    return ''.join(ch.lower() if ch.isalnum() else '_' for ch in name).strip('_')


def suggest_hunter_prefix(target: str, vuln_slug: str) -> str:
    base = _normalize_name(target)
    slug = _normalize_name(vuln_slug)
    return f"{base}_{slug}" if slug else base


def classify_burp_exports(directory: str, prefix: str = '') -> Dict[str, List[str] | str]:
    path = Path(directory)
    result = {
        'request_file': '',
        'response_file': '',
        'screenshot_files': [],
        'evidence_files': [],
        'matched_files': [],
    }
    if not path.exists():
        return result

    prefix_key = _normalize_name(prefix) if prefix else ''
    for file in path.iterdir():
        if not file.is_file():
            continue
        key = _normalize_name(file.name)
        if prefix_key and prefix_key not in key:
            continue
        result['matched_files'].append(str(file))
        suffix = file.suffix.lower()
        name = file.name.lower()
        if 'request' in name and not result['request_file']:
            result['request_file'] = str(file)
        elif 'response' in name and not result['response_file']:
            result['response_file'] = str(file)
        elif suffix in {'.png', '.jpg', '.jpeg', '.webp'} or 'screenshot' in name:
            result['screenshot_files'].append(str(file))
        else:
            result['evidence_files'].append(str(file))
    return result
