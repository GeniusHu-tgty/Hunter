from pathlib import Path
from typing import Dict

from .burp_adapter import classify_burp_exports, suggest_hunter_prefix


def import_burp_evidence(source_dir: str, target: str, vuln_slug: str, destination_dir: str) -> Dict[str, object]:
    source = Path(source_dir)
    destination = Path(destination_dir)
    destination.mkdir(parents=True, exist_ok=True)

    prefix = suggest_hunter_prefix(target, vuln_slug)
    classified = classify_burp_exports(str(source), prefix='')

    copied = []
    for key in ['request_file', 'response_file']:
        path = classified.get(key)
        if path:
            src = Path(path)
            dst = destination / f'{prefix}_{src.name}'
            dst.write_bytes(src.read_bytes())
            classified[key] = str(dst)
            copied.append(str(dst))

    for list_key in ['screenshot_files', 'evidence_files', 'matched_files']:
        new_values = []
        for path in classified.get(list_key, []):
            src = Path(path)
            dst = destination / f'{prefix}_{src.name}'
            if not dst.exists():
                dst.write_bytes(src.read_bytes())
            new_values.append(str(dst))
            copied.append(str(dst))
        classified[list_key] = new_values

    classified['prefix'] = prefix
    classified['copied_files'] = sorted(set(copied))
    return classified
