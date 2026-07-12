from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse

LANES = ("web", "api", "source", "javascript", "pe", "apk", "firmware", "script", "document", "protocol", "capture", "pwn", "crypto", "mixed")


def classify(item):
    path = str(item.get("path", "")).lower()
    url = str(item.get("url", "")).lower()
    hint = str(item.get("kind", "")).lower()
    magic = str(item.get("magic", "")).lower()
    if hint in LANES: return hint, "kind"
    if magic.startswith("mz") or "portable executable" in magic: return "pe", "magic"
    if magic.startswith("\x7felf") or magic.startswith("elf"): return "pwn", "magic"
    if "android" in magic or "dex" in magic: return "apk", "magic"
    if "pcap" in magic: return "capture", "magic"
    ext = Path(urlparse(url).path or path).suffix.lower()
    if ext in {".exe", ".dll", ".sys"}: return "pe", "extension"
    if ext in {".elf", ".so", ".dylib"}: return "pwn", "extension"
    if ext in {".apk", ".aab", ".ipa"}: return "apk", "extension"
    if ext in {".js", ".mjs", ".ts", ".wasm"}: return "javascript", "extension"
    if ext in {".pcap", ".pcapng"}: return "capture", "extension"
    if ext in {".bin", ".img", ".fw"}: return "firmware", "extension"
    if ext in {".py", ".ps1", ".sh", ".lua"}: return "script", "extension"
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx"}: return "document", "extension"
    if url: return ("api" if any(x in url for x in ("/api", "graphql", ".json")) else "web"), "url"
    return "source", "default"


def route(inputs):
    classified = [classify(item) for item in inputs or []]
    detected = [lane for lane, _ in classified]
    unique = list(dict.fromkeys(detected))
    primary = unique[0] if len(unique) == 1 else ("mixed" if len(unique) > 1 else "source")
    return {"primary_lane": primary, "secondary_lanes": unique if primary == "mixed" else [], "confidence": 0.95 if unique else 0.4, "signals": [{"input": item, "lane": lane, "source": source} for item, (lane, source) in zip(inputs or [], classified)]}
