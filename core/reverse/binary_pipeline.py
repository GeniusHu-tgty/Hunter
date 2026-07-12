"""Stdlib-only binary reverse-engineering analysis pipeline."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import tempfile
import threading
import uuid
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}

_FIRMWARE_MAGICS = (
    (0, b"\x27\x05\x19\x56"),
    (0, b"UBI#"),
    (0, b"HDR0"),
    (0, b"hsqs"),
    (0, b"sqsh"),
    (0, b"qshs"),
    (0, b"shsq"),
    (0, b"\xd0\x0d\xfe\xed"),
    (0, b"CrAU"),
    (257, b"ustar"),
)

_PACKER_MARKERS = {
    "UPX": (b"UPX!", b"UPX0", b"UPX1", b"UPX2", b"UPX3"),
    "ASPack": (b"ASPack", b".aspack", b".adata"),
    "Themida": (b"Themida", b"WinLicense", b".themida"),
    "VMProtect": (b"VMProtect", b".vmp0", b".vmp1", b".vmp2"),
}

_IMPORT_CATEGORIES = {
    "crypto": (
        "crypt",
        "bcrypt",
        "aes",
        "rsa",
        "sha",
        "md5",
        "evp_",
        "cipher",
        "chacha",
        "sodium",
    ),
    "network": (
        "winhttp",
        "wininet",
        "internetopen",
        "httpsendrequest",
        "socket",
        "connect",
        "send",
        "recv",
        "getaddrinfo",
        "curl_",
        "wsastartup",
        "urlopen",
    ),
    "anti_debug": (
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstring",
        "ptrace",
        "queryperformancecounter",
        "gettickcount",
    ),
    "persistence": (
        "regsetvalue",
        "createservice",
        "startservice",
        "schtasks",
        "writeprivateprofilestring",
        "copyfile",
        "movefile",
    ),
    "process": (
        "createprocess",
        "shellexecute",
        "winexec",
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "loadlibrary",
        "getprocaddress",
        "dlopen",
        "dlsym",
    ),
    "filesystem": (
        "createfile",
        "readfile",
        "writefile",
        "deletefile",
        "fopen",
        "fread",
        "fwrite",
        "unlink",
    ),
}

_KNOWN_IMPORTS = (
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContextW",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptOpenAlgorithmProvider",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpSendRequest",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "getaddrinfo",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "RegSetValueExA",
    "RegSetValueExW",
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecuteA",
    "ShellExecuteW",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "ptrace",
    "dlopen",
    "dlsym",
    "EVP_EncryptInit_ex",
    "EVP_DecryptInit_ex",
    "SSL_connect",
)

_COMPILER_MARKERS = (
    ("MSVC", "compiler", (b"Microsoft Visual C++", b"Rich", b"MSVCP", b"VCRUNTIME")),
    ("MinGW/GCC", "compiler", (b"MinGW", b"GCC:", b"libgcc", b"__gcc_register_frame")),
    ("Clang/LLVM", "compiler", (b"clang version", b"LLVM", b"__clang")),
    ("Delphi", "language", (b"Embarcadero Delphi", b"Borland Delphi", b"System.SysUtils")),
    ("Go", "language", (b"Go build ID:", b"runtime.main", b"runtime.goexit", b"gopclntab")),
    ("Rust", "language", (b"rust_eh_personality", b"core::panicking", b"alloc::", b"rustc")),
    (".NET", "runtime", (b"BSJB", b"mscoree.dll", b"_CorExeMain", b"System.Runtime")),
    ("Python/PyInstaller", "language", (b"PyInstaller", b"python3", b"PYZ-00.pyz", b"Py_Initialize")),
    ("AutoIt", "language", (b"AutoIt v3", b"AU3!EA06")),
    ("NSIS", "installer", (b"Nullsoft", b"NSIS Error")),
    ("Node.js/Electron", "runtime", (b"Electron", b"node.dll", b"NODE_MODULE_VERSION")),
    ("Java/Kotlin", "language", (b"java/lang/", b"kotlin/", b"Ljava/", b"javax.crypto")),
)

_CATEGORY_PATTERNS = {
    "crypto": (
        "crypt",
        "bcrypt",
        "aes",
        "rsa",
        "sha",
        "md5",
        "cipher",
        "chacha",
        "salsa",
        "hmac",
        "pkcs",
        "evp_",
        "javax.crypto",
    ),
    "network": (
        "winhttp",
        "wininet",
        "httpsendrequest",
        "internetconnect",
        "socket",
        "connect",
        "send",
        "recv",
        "getaddrinfo",
        "curl",
        "okhttp",
        "http://",
        "https://",
    ),
    "anti_debug": (
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstring",
        "ptrace",
        "queryperformancecounter",
        "gettickcount",
        "beingdebugged",
    ),
    "persistence": (
        "regsetvalue",
        "createservice",
        "startservice",
        "currentversion\\run",
        "currentversion/run",
        "startup",
        "schtasks",
        "launchagents",
        "systemd",
        "cron",
    ),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def _read_prefix(path: Path, size: int = 4096) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def detect_binary_type(sample_path: os.PathLike[str] | str) -> str:
    """Detect a supported binary family using file contents rather than suffixes."""

    path = Path(sample_path)
    prefix = _read_prefix(path)
    if prefix.startswith(b"MZ"):
        return "pe"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix[:4] in _MACHO_MAGICS:
        return "mach-o"
    if prefix.startswith(b"dex\n") and len(prefix) >= 8 and prefix[7:8] == b"\x00":
        return "dex"
    if prefix.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(path) as archive:
                names = set(archive.namelist())
            if "AndroidManifest.xml" in names and any(
                name == "classes.dex" or re.fullmatch(r"classes\d+\.dex", name)
                for name in names
            ):
                return "apk"
        except (OSError, zipfile.BadZipFile):
            pass
    if any(prefix[offset : offset + len(magic)] == magic for offset, magic in _FIRMWARE_MAGICS):
        return "firmware"
    if prefix.startswith(b"#!"):
        return "script"
    return "unknown"


def detect_binary_type_details(sample_path: os.PathLike[str] | str) -> dict[str, Any]:
    """Return type metadata while preserving the string-only detector API."""

    path = Path(sample_path).expanduser().resolve()
    binary_type = detect_binary_type(path)
    details = {
        "type": binary_type,
        "sample_path": str(path),
        "size": path.stat().st_size,
        "magic_hex": _read_prefix(path, 16).hex(),
        "confidence": 0.0 if binary_type == "unknown" else 0.98,
        "signals": [],
    }
    if binary_type == "pe":
        prefix = _read_prefix(path, 4096)
        valid_pe_header = False
        if len(prefix) >= 64:
            pe_offset = int.from_bytes(prefix[60:64], "little")
            if pe_offset + 4 <= len(prefix):
                valid_pe_header = prefix[pe_offset : pe_offset + 4] == b"PE\x00\x00"
        details["confidence"] = 0.99 if valid_pe_header else 0.55
        details["signals"] = ["magic:MZ", "header:PE" if valid_pe_header else "header:unverified"]
    elif binary_type != "unknown":
        details["signals"] = [f"magic:{binary_type}"]
    if binary_type == "apk":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
        details["apk_entries"] = len(names)
        details["dex_files"] = sorted(
            name
            for name in names
            if name == "classes.dex" or re.fullmatch(r"classes\d+\.dex", name)
        )
    return details


def compute_hashes(sample_path: os.PathLike[str] | str) -> dict[str, str]:
    """Compute MD5, SHA-1, and SHA-256 in one streaming pass."""

    digests = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with Path(sample_path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


calculate_hashes = compute_hashes


def extract_strings(data: bytes, minimum_length: int = 4) -> list[dict[str, Any]]:
    """Extract printable ASCII and UTF-16LE strings with offsets."""

    if minimum_length < 2:
        raise ValueError("minimum_length must be at least 2")
    findings: list[dict[str, Any]] = []
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum_length).encode() + rb",}")
    wide_pattern = re.compile(
        rb"(?:[\x20-\x7e]\x00){" + str(minimum_length).encode() + rb",}"
    )
    occupied: set[tuple[int, int]] = set()
    for match in ascii_pattern.finditer(data):
        findings.append(
            {
                "value": match.group().decode("ascii", errors="replace"),
                "offset": match.start(),
                "encoding": "ascii",
            }
        )
        occupied.add((match.start(), match.end()))
    for match in wide_pattern.finditer(data):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        findings.append(
            {
                "value": match.group().decode("utf-16le", errors="replace"),
                "offset": match.start(),
                "encoding": "utf-16le",
            }
        )
    findings.sort(key=lambda item: (item["offset"], item["encoding"]))
    return findings


def _string_category(value: str) -> str:
    lowered = value.lower()
    if re.search(r"https?://", value, re.IGNORECASE):
        return "urls"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        try:
            ipaddress.ip_address(value)
            return "ip_addresses"
        except ValueError:
            pass
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", lowered):
        return "domains"
    if "currentversion\\run" in lowered or "currentversion/run" in lowered:
        return "persistence"
    if lowered.startswith(("hkey_", "hkcu\\", "hklm\\")) or "\\registry\\" in lowered:
        return "registry"
    if re.search(r"(?:[a-z]:\\|/etc/|/usr/|/tmp/|/var/|\\\\[^\\]+\\)", value, re.IGNORECASE):
        return "paths"
    if any(token in lowered for token in _CATEGORY_PATTERNS["crypto"]):
        return "crypto"
    if any(token in lowered for token in _CATEGORY_PATTERNS["anti_debug"]):
        return "anti_debug"
    if any(token in lowered for token in ("cmd.exe", "powershell", "/bin/sh", "bash -c", "rundll32")):
        return "commands"
    if any(token in lowered for token in ("mozilla/", "user-agent", "curl/", "wget/")):
        return "user_agents"
    return "other"


def group_strings(strings: Iterable[Mapping[str, Any] | str]) -> dict[str, list[dict[str, Any]]]:
    """Group strings into analyst-oriented semantic buckets."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in strings:
        entry = dict(item) if isinstance(item, Mapping) else {"value": str(item)}
        entry.setdefault("value", "")
        grouped[_string_category(str(entry["value"]))].append(entry)
    return {category: values for category, values in sorted(grouped.items())}


semantic_group_strings = group_strings


def extract_imports(data: bytes) -> list[dict[str, Any]]:
    """Recover recognizable imported API names from raw binary data."""

    findings: list[dict[str, Any]] = []
    lowered = data.lower()
    for name in _KNOWN_IMPORTS:
        marker = name.encode("ascii").lower()
        start = 0
        while True:
            offset = lowered.find(marker, start)
            if offset < 0:
                break
            findings.append({"name": name, "offset": offset})
            start = offset + len(marker)
    findings.sort(key=lambda item: (item["offset"], item["name"]))
    deduplicated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in findings:
        key = item["name"].lower()
        if key not in seen:
            deduplicated.append(item)
            seen.add(key)
    return deduplicated


def _import_category(name: str) -> str:
    lowered = name.lower()
    for category, tokens in _IMPORT_CATEGORIES.items():
        if any(token in lowered for token in tokens):
            return category
    return "other"


def group_imports(imports: Iterable[Mapping[str, Any] | str]) -> dict[str, list[dict[str, Any]]]:
    """Group imported APIs by behavior."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in imports:
        entry = dict(item) if isinstance(item, Mapping) else {"name": str(item)}
        entry.setdefault("name", "")
        grouped[_import_category(str(entry["name"]))].append(entry)
    return {category: values for category, values in sorted(grouped.items())}


semantic_group_imports = group_imports


def detect_packers(
    data: bytes,
    section_names: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Detect common packers and high-confidence custom packing signals."""

    sections = [str(section) for section in (section_names or [])]
    section_blob = "\n".join(sections).encode("utf-8", errors="ignore")
    haystack = data + b"\n" + section_blob
    detected: list[str] = []
    evidence: dict[str, list[str]] = {}
    confidences: list[float] = []
    for name, markers in _PACKER_MARKERS.items():
        matched = [
            marker.decode("latin-1")
            for marker in markers
            if marker.lower() in haystack.lower()
        ]
        if matched:
            detected.append(name)
            evidence[name] = matched
            confidences.append(min(0.99, 0.72 + (0.08 * len(matched))))
    custom_evidence: list[str] = []
    suspicious_sections = [
        section
        for section in sections
        if re.search(r"(pack|protect|crypt|stub|obfus|\.vmp|upx)", section, re.IGNORECASE)
        and not any(section.lower().startswith(prefix) for prefix in (".upx", "upx", ".vmp"))
    ]
    if suspicious_sections:
        custom_evidence.extend(f"suspicious section {section}" for section in suspicious_sections)
    entropy = _shannon_entropy(data)
    printable_ratio = (
        sum(1 for byte in data if byte in b"\t\r\n" or 32 <= byte <= 126) / len(data)
        if data
        else 0.0
    )
    if len(data) >= 512 and entropy >= 7.2 and printable_ratio <= 0.2:
        custom_evidence.append(f"high entropy {entropy:.3f}")
    if re.search(rb"custom[\s_-]*pack(?:er|ed)?", data, re.IGNORECASE):
        custom_evidence.append("custom packer marker")
    if custom_evidence:
        detected.append("custom")
        evidence["custom"] = custom_evidence
        confidences.append(0.7 if len(custom_evidence) == 1 else 0.86)
    detected = list(dict.fromkeys(detected))
    return {
        "detected": detected,
        "requires_unpacking": bool(detected),
        "confidence": round(max(confidences, default=0.0), 3),
        "evidence": evidence,
        "entropy": round(entropy, 3),
    }


def detect_compiler_language(
    data: bytes,
    imports: Sequence[Mapping[str, Any] | str] | None = None,
    strings: Sequence[Mapping[str, Any] | str] | None = None,
) -> dict[str, Any]:
    """Detect likely compilers, runtimes, and source languages from markers."""

    extra = []
    for item in imports or []:
        extra.append(str(item.get("name", "")) if isinstance(item, Mapping) else str(item))
    for item in strings or []:
        extra.append(str(item.get("value", "")) if isinstance(item, Mapping) else str(item))
    haystack = data + "\n".join(extra).encode("utf-8", errors="ignore")
    lowered = haystack.lower()
    detections: list[dict[str, Any]] = []
    for name, kind, markers in _COMPILER_MARKERS:
        matched = [
            marker.decode("latin-1")
            for marker in markers
            if marker.lower() in lowered
        ]
        if matched:
            detections.append(
                {
                    "name": name,
                    "kind": kind,
                    "confidence": round(min(0.98, 0.65 + 0.1 * len(matched)), 3),
                    "evidence": matched,
                }
            )
    detections.sort(key=lambda item: (-item["confidence"], item["name"]))
    compiler = next((item["name"] for item in detections if item["kind"] == "compiler"), None)
    language = next(
        (item["name"] for item in detections if item["kind"] in {"language", "runtime"}),
        None,
    )
    return {
        "detected": detections,
        "compiler": compiler,
        "language": language,
        "confidence": detections[0]["confidence"] if detections else 0.0,
    }


detect_compiler = detect_compiler_language


def _function_name(item: Mapping[str, Any], fallback: str) -> str:
    return str(item.get("function") or item.get("address") or fallback)


def _add_function_evidence(
    aggregate: dict[tuple[str, str], dict[str, Any]],
    category: str,
    function: str,
    confidence: float,
    evidence: str,
    evidence_quality: str = "xref-confirmed",
) -> None:
    key = (category, function)
    if key not in aggregate:
        aggregate[key] = {
            "category": category,
            "function": function,
            "confidence": confidence,
            "evidence": [],
            "evidence_quality": evidence_quality,
        }
    aggregate[key]["confidence"] = max(aggregate[key]["confidence"], confidence)
    if evidence not in aggregate[key]["evidence"]:
        aggregate[key]["evidence"].append(evidence)


def identify_key_functions(
    imports: Sequence[Mapping[str, Any] | str],
    strings: Sequence[Mapping[str, Any] | str],
    call_graph: Mapping[str, Sequence[str] | Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Identify functions related to crypto, networking, anti-debug, C2, and persistence."""

    aggregate: dict[tuple[str, str], dict[str, Any]] = {}
    functions_by_category: dict[str, set[str]] = defaultdict(set)
    normalized_imports = [
        dict(item) if isinstance(item, Mapping) else {"name": str(item)}
        for item in imports
    ]
    normalized_strings = [
        dict(item) if isinstance(item, Mapping) else {"value": str(item)}
        for item in strings
    ]
    for item in normalized_imports:
        name = str(item.get("name", ""))
        lowered = name.lower()
        confirmed_function = str(item.get("function", "")).strip()
        function = confirmed_function or f"api:{name or 'unknown'}"
        confidence = 0.88 if confirmed_function else 0.5
        evidence_quality = "xref-confirmed" if confirmed_function else "heuristic-indicator"
        for category in ("crypto", "network", "anti_debug", "persistence"):
            if any(token in lowered for token in _CATEGORY_PATTERNS[category]):
                _add_function_evidence(
                    aggregate,
                    category,
                    function,
                    confidence,
                    f"import {name}",
                    evidence_quality,
                )
                functions_by_category[category].add(function)
    direct_c2_functions: set[str] = set()
    for item in normalized_strings:
        value = str(item.get("value", ""))
        lowered = value.lower()
        confirmed_function = str(item.get("function", "")).strip()
        function = confirmed_function or f"string:{item.get('address', 'unknown')}"
        confidence = 0.76 if confirmed_function else 0.45
        evidence_quality = "xref-confirmed" if confirmed_function else "heuristic-indicator"
        for category in ("crypto", "anti_debug", "persistence"):
            if any(token in lowered for token in _CATEGORY_PATTERNS[category]):
                _add_function_evidence(
                    aggregate,
                    category,
                    function,
                    confidence,
                    f"string {value[:160]}",
                    evidence_quality,
                )
                functions_by_category[category].add(function)
        if value.lower().startswith(("http://", "https://")):
            _add_function_evidence(
                aggregate,
                "network",
                function,
                0.78 if confirmed_function else 0.48,
                f"URL {value[:160]}",
                evidence_quality,
            )
            functions_by_category["network"].add(function)
            if re.search(r"(?:c2|gate|beacon|command|panel|bot|/api(?:/|$))", lowered):
                _add_function_evidence(
                    aggregate,
                    "c2",
                    function,
                    0.84 if confirmed_function else 0.55,
                    f"probable C2 URL {value[:160]}",
                    evidence_quality,
                )
                direct_c2_functions.add(function)
                functions_by_category["c2"].add(function)
    graph = call_graph or {}
    for caller, raw_callees in graph.items():
        if isinstance(raw_callees, Mapping):
            callees = [str(name) for name in raw_callees]
        else:
            callees = [str(name) for name in raw_callees]
        called_categories = {
            category
            for category, functions in functions_by_category.items()
            if functions.intersection(callees)
        }
        if "network" in called_categories and (
            "crypto" in called_categories
            or "c2" in called_categories
            or direct_c2_functions.intersection(callees)
        ):
            _add_function_evidence(
                aggregate,
                "c2",
                str(caller),
                0.93,
                "orchestrates network and crypto/C2 callees",
            )
            functions_by_category["c2"].add(str(caller))
    category_order = {
        "crypto": 0,
        "network": 1,
        "anti_debug": 2,
        "c2": 3,
        "persistence": 4,
    }
    return sorted(
        aggregate.values(),
        key=lambda item: (
            category_order.get(item["category"], 99),
            -item["confidence"],
            item["function"],
        ),
    )


class BinaryPipeline:
    """Persistent, subclass-friendly binary reverse pipeline."""

    STEPS = ("triage", "static", "identify", "plan", "capture", "produce")

    def __init__(
        self,
        sample_path: os.PathLike[str] | str,
        output_root: os.PathLike[str] | str | None = None,
        backend_runner: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
        output_dir: os.PathLike[str] | str | None = None,
        pipeline_id: str | None = None,
    ) -> None:
        self.sample_path = Path(sample_path).expanduser().resolve()
        if not self.sample_path.is_file():
            raise FileNotFoundError(f"sample not found: {self.sample_path}")
        if output_root is not None and output_dir is not None:
            raise ValueError("output_root and output_dir are mutually exclusive")
        self._requested_pipeline_id = pipeline_id or f"reverse-{uuid.uuid4().hex[:12]}"
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self._requested_pipeline_id)
            or ".." in self._requested_pipeline_id
        ):
            raise ValueError("pipeline_id must be a safe relative identifier")
        output_root_path = Path(output_root).expanduser().resolve() if output_root is not None else None
        selected_output = (
            output_dir
            if output_dir is not None
            else output_root_path / self._requested_pipeline_id
            if output_root_path is not None
            else None
        )
        self.output_dir = (
            Path(selected_output).expanduser().resolve()
            if selected_output is not None
            else self.sample_path.parent / f"{self.sample_path.stem}.reverse"
        )
        if output_root_path is not None:
            resolved_output = self.output_dir.resolve()
            if resolved_output != output_root_path and output_root_path not in resolved_output.parents:
                raise ValueError("pipeline_id resolves outside output_root")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.backend_runner = backend_runner
        self._state_lock = threading.RLock()
        self.state = self._load_or_create_state()
        self._loaded_revision = int(self.state.get("revision", 0))
        self._persist_state()

    @property
    def pipeline_id(self) -> str:
        return str(self.state["pipeline_id"])

    @classmethod
    def load(
        cls,
        pipeline_id: str,
        output_root: os.PathLike[str] | str,
        backend_runner: Callable[[str, str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> "BinaryPipeline":
        """Reopen a persisted pipeline by ID from an output root."""

        root = Path(output_root).expanduser().resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"output root not found: {root}")
        candidates = [root / "state.json"]
        candidates.extend(path for path in root.rglob("state.json") if path != candidates[0])
        for state_path in candidates:
            if not state_path.is_file():
                continue
            resolved_state = state_path.resolve()
            if resolved_state != root / "state.json" and root not in resolved_state.parents:
                raise ValueError("pipeline state resolves outside output_root")
            try:
                persisted = json.loads(resolved_state.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if persisted.get("pipeline_id") != pipeline_id:
                continue
            return cls(
                persisted["sample_path"],
                output_dir=resolved_state.parent,
                backend_runner=backend_runner,
                pipeline_id=pipeline_id,
            )
        raise FileNotFoundError(f"pipeline state not found: {pipeline_id}")

    def _load_or_create_state(self) -> dict[str, Any]:
        state_path = self.output_dir / "state.json"
        if state_path.is_file():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            recorded_sample = Path(state.get("sample_path", "")).expanduser().resolve()
            if recorded_sample != self.sample_path:
                raise ValueError(
                    f"output directory already belongs to another sample: {recorded_sample}"
                )
            current_fingerprint = {
                "size": self.sample_path.stat().st_size,
                "sha256": compute_hashes(self.sample_path)["sha256"],
            }
            expected_fingerprint = state.get("sample_fingerprint", {})
            if not expected_fingerprint:
                triage = state.get("results", {}).get("triage", {})
                expected_fingerprint = {
                    "size": triage.get("size"),
                    "sha256": triage.get("hashes", {}).get("sha256"),
                }
            if (
                expected_fingerprint.get("size") is not None
                and expected_fingerprint.get("size") != current_fingerprint["size"]
            ) or (
                expected_fingerprint.get("sha256")
                and expected_fingerprint.get("sha256") != current_fingerprint["sha256"]
            ):
                raise ValueError("sample fingerprint changed since the pipeline was created")
            state["sample_fingerprint"] = current_fingerprint
            existing_steps = {
                item["name"]: item
                for item in state.get("steps", [])
                if isinstance(item, Mapping) and item.get("name")
            }
            state["steps"] = [
                existing_steps.get(name, {"name": name, "status": "pending"})
                for name in self.STEPS
            ]
            state.setdefault("results", {})
            state.setdefault("artifacts", {})
            state.setdefault("handoffs", [])
            state.setdefault("errors", [])
            state.setdefault("next_actions", [])
            state.setdefault("revision", 0)
            state["state_path"] = str(state_path.resolve())
            state["output_dir"] = str(self.output_dir)
            return state
        now = _utc_now()
        sample_fingerprint = {
            "size": self.sample_path.stat().st_size,
            "sha256": compute_hashes(self.sample_path)["sha256"],
        }
        return {
            "schema_version": "1.0",
            "pipeline_id": self._requested_pipeline_id,
            "sample_path": str(self.sample_path),
            "output_dir": str(self.output_dir),
            "state_path": str(state_path.resolve()),
            "sample_fingerprint": sample_fingerprint,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
            "steps": [{"name": name, "status": "pending"} for name in self.STEPS],
            "results": {},
            "artifacts": {},
            "handoffs": [],
            "errors": [],
            "next_actions": [],
            "revision": 0,
        }

    def _step_record(self, name: str) -> dict[str, Any]:
        for step in self.state["steps"]:
            if step["name"] == name:
                return step
        raise ValueError(f"unknown pipeline step: {name}")

    def _refresh_pipeline_status(self) -> None:
        statuses = [step["status"] for step in self.state["steps"]]
        if "failed" in statuses:
            self.state["status"] = "failed"
        elif all(status == "completed" for status in statuses):
            self.state["status"] = "completed"
        elif "awaiting-external" in statuses:
            self.state["status"] = "awaiting-external"
        elif "running" in statuses:
            self.state["status"] = "running"
        else:
            self.state["status"] = "pending"

    def _persist_state(self) -> str:
        """Atomically persist the current state and return its path."""

        with self._state_lock:
            self.state["updated_at"] = _utc_now()
            self._refresh_pipeline_status()
            state_path = Path(self.state["state_path"])
            state_path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_current_revision()
            next_revision = self._loaded_revision + 1
            self.state["revision"] = next_revision
            payload = json.dumps(self.state, ensure_ascii=False, indent=2, sort_keys=True)
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=f".{state_path.name}.",
                suffix=".tmp",
                dir=state_path.parent,
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_path, state_path)
                self._loaded_revision = next_revision
            finally:
                if os.path.exists(temporary_path):
                    os.unlink(temporary_path)
            return str(state_path)

    def _assert_current_revision(self) -> None:
        state_path = Path(self.state["state_path"])
        if not state_path.is_file():
            return
        persisted = json.loads(state_path.read_text(encoding="utf-8"))
        current_revision = int(persisted.get("revision", 0))
        if current_revision != self._loaded_revision:
            raise RuntimeError(
                "concurrent pipeline modification detected: "
                f"expected revision {self._loaded_revision}, found {current_revision}"
            )

    def _write_artifact(
        self,
        name: str,
        relative_path: os.PathLike[str] | str,
        content: str | bytes | Mapping[str, Any] | Sequence[Any],
    ) -> str:
        """Atomically write an artifact within the pipeline output directory."""

        self._assert_current_revision()
        artifact_path = (self.output_dir / Path(relative_path)).resolve()
        try:
            artifact_path.relative_to(self.output_dir.resolve())
        except ValueError as exc:
            raise ValueError("artifact path must stay inside output_dir") from exc
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            payload = content
        elif isinstance(content, str):
            payload = content.encode("utf-8")
        else:
            payload = json.dumps(
                content,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{artifact_path.name}.",
            suffix=".tmp",
            dir=artifact_path.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, artifact_path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
        self.state["artifacts"][name] = str(artifact_path)
        self._persist_state()
        return str(artifact_path)

    def _run_backend(self, descriptor: dict[str, Any]) -> dict[str, Any] | None:
        runner = self.backend_runner
        if runner is None:
            return None
        result = runner(
            descriptor["server"],
            descriptor["tool"],
            dict(descriptor["arguments"]),
        )
        if not isinstance(result, dict):
            raise TypeError("backend_runner must return a dict")
        return result

    def _external_handoff(
        self,
        server: str,
        tool: str,
        arguments: Mapping[str, Any],
        purpose: str,
        execute: bool = True,
    ) -> dict[str, Any]:
        """Create an external MCP descriptor and optionally execute it."""

        normalized_arguments = _json_safe(arguments)
        for existing in self.state["handoffs"]:
            if (
                existing.get("server") == server
                and existing.get("tool") == tool
                and existing.get("arguments") == normalized_arguments
                and existing.get("purpose") == purpose
            ):
                descriptor = existing
                break
        else:
            descriptor = {
                "handoff_id": f"handoff-{uuid.uuid4().hex[:12]}",
                "server": server,
                "tool": tool,
                "arguments": normalized_arguments,
                "purpose": purpose,
                "execution": "external-mcp",
                "status": "pending",
                "created_at": _utc_now(),
            }
            self.state["handoffs"].append(descriptor)
        if execute and self.backend_runner is not None and descriptor.get("status") != "completed":
            try:
                result = self._run_backend(descriptor)
            except Exception as exc:
                descriptor["status"] = "failed"
                descriptor["error"] = f"{type(exc).__name__}: {exc}"
                descriptor["updated_at"] = _utc_now()
                self._persist_state()
                raise
            descriptor["result"] = _json_safe(result)
            external_status = result.get("status") if isinstance(result, Mapping) else None
            implicit_error = (
                external_status is None
                and (
                    bool(result.get("error"))
                    or result.get("ok") is False
                    or result.get("success") is False
                )
            )
            if external_status in {"ok", "success", "completed"} or (
                external_status is None and not implicit_error
            ):
                descriptor["status"] = "completed"
                descriptor.pop("error", None)
            elif external_status in {"pending", "deferred", "awaiting-external"}:
                descriptor["status"] = "pending"
                descriptor.pop("error", None)
            else:
                descriptor["status"] = "failed"
                descriptor["error"] = str(
                    result.get("error")
                    or result.get("message")
                    or f"{tool} returned status {external_status}"
                )
            descriptor["updated_at"] = _utc_now()
            if descriptor["status"] == "failed":
                self._persist_state()
                raise RuntimeError(descriptor["error"])
        self._persist_state()
        return descriptor

    def run_step(self, name: str) -> dict[str, Any]:
        with self._state_lock:
            return self._run_step_locked(name)

    def _run_step_locked(self, name: str) -> dict[str, Any]:
        """Run one named step and return the complete persistent state."""

        if name not in self.STEPS:
            raise ValueError(f"unknown pipeline step: {name}")
        self._assert_current_revision()
        for dependency in self.STEPS[: self.STEPS.index(name)]:
            dependency_step = self._step_record(dependency)
            if dependency_step["status"] == "failed":
                raise RuntimeError(f"dependency step failed: {dependency}")
            if dependency_step["status"] == "pending":
                self._run_step_locked(dependency)
        step = self._step_record(name)
        if step["status"] == "completed":
            return self.state
        step["status"] = "running"
        step["started_at"] = _utc_now()
        step.pop("error", None)
        self._persist_state()
        try:
            method = getattr(self, f"_step_{name}", None)
            if method is None or not callable(method):
                raise NotImplementedError(f"pipeline step is not implemented: {name}")
            raw_result = method()
            if raw_result is None:
                result: dict[str, Any] = {}
                step_status = "completed"
            elif isinstance(raw_result, tuple) and len(raw_result) == 2:
                step_status = str(raw_result[0])
                result = _json_safe(dict(raw_result[1]))
            else:
                result = _json_safe(dict(raw_result))
                explicit_status = result.pop("_step_status", None)
                if explicit_status is None and result.get("status") in {
                    "completed",
                    "awaiting-external",
                }:
                    explicit_status = result["status"]
                step_status = str(explicit_status or "completed")
            if step_status not in {"completed", "awaiting-external"}:
                raise ValueError(f"invalid step status returned by {name}: {step_status}")
            if name == "produce" and any(
                item["status"] == "awaiting-external"
                for item in self.state["steps"][: self.STEPS.index(name)]
            ):
                result["partial"] = True
                step_status = "awaiting-external"
            self.state["results"][name] = result
            step["status"] = step_status
            step["completed_at"] = _utc_now()
            step["result_keys"] = sorted(result)
        except Exception as exc:
            step["status"] = "failed"
            step["completed_at"] = _utc_now()
            step["error"] = f"{type(exc).__name__}: {exc}"
            self.state["errors"].append(
                {
                    "step": name,
                    "error": step["error"],
                    "timestamp": _utc_now(),
                }
            )
            self._persist_state()
            raise
        self._persist_state()
        if name == "produce":
            self._rewrite_report_json()
        return self.state

    def run_all(self) -> dict[str, Any]:
        """Run all steps in declared order and return the persistent state."""

        for name in self.STEPS:
            self.run_step(name)
        return self.state

    def extract_iocs(self) -> dict[str, Any]:
        """Extract normalized IOC data for MCP wrappers."""

        if self._step_record("triage")["status"] != "completed":
            self.run_step("triage")
        if "static" in self.STEPS:
            if self._step_record("static")["status"] != "completed":
                self.run_step("static")
        elif "static" not in self.state["results"]:
            self.state["results"]["static"] = _json_safe(self._step_static())
            self._persist_state()
        result = self._build_iocs()
        self._rewrite_report_json()
        return result

    def generate_rules(self) -> dict[str, str]:
        """Generate YARA, Sigma, and IOC artifacts and return their paths."""

        iocs = self.extract_iocs()
        result = {
            "yara_rule": self._write_artifact(
                "yara_rule",
                "reports/sample.yar",
                self._render_yara(iocs),
            ),
            "sigma_rule": self._write_artifact(
                "sigma_rule",
                "reports/sample.sigma.yml",
                self._render_sigma(iocs),
            ),
            "iocs": self._write_artifact("iocs", "reports/iocs.json", iocs),
        }
        self._rewrite_report_json()
        return result

    def _rewrite_report_json(self) -> None:
        report_path_value = self.state.get("artifacts", {}).get("report_json")
        if not report_path_value:
            return
        report_path = Path(report_path_value)
        snapshot = json.loads(json.dumps(self.state, ensure_ascii=False, default=str))
        snapshot["ioc_summary"] = self._build_iocs()
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{report_path.name}.",
            suffix=".tmp",
            dir=report_path.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(snapshot, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, report_path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def decrypt_plan(self) -> dict[str, Any]:
        """Generate the decrypt/unpack plan used by MCP wrappers."""

        if self._step_record("triage")["status"] != "completed":
            self.run_step("triage")
        triage = self.state["results"]["triage"]
        content = self._render_unpack_plan(triage)
        path = self._write_artifact(
            "decrypt_unpack_plan",
            "plans/decrypt-unpack-plan.md",
            content,
        )
        if triage.get("binary_type") == "pe":
            handoffs = [
                self._external_handoff(
                    "reverse_lab_tools",
                    "make_pe_crypto_unpack_plan",
                    {
                        "sample_path": str(self.sample_path),
                        "mode": "both",
                        "output_path": str(self.output_dir / "external" / "crypto-unpack-plan.json"),
                        "include_frida": True,
                    },
                    "Generate the backend-specific x64dbg and Windows Frida decrypt/unpack package.",
                    execute=False,
                )
            ]
        else:
            handoffs = [
                self._external_handoff(
                    "frida",
                    "run_script",
                    {
                        "target": str(self.sample_path),
                        "script_source": self._render_frida_script(
                            self.state["results"].get("static", {}).get("imports", []),
                            triage.get("binary_type", "unknown"),
                        ),
                        "mode": "spawn",
                        "duration_seconds": 30,
                        "output_path": str(self.output_dir / "captures" / "crypto-unpack.json"),
                    },
                    "Trace crypto and loader operations for the detected non-PE binary family.",
                    execute=False,
                )
            ]
        return {
            "path": path,
            "content": content,
            "requires_unpacking": bool(triage.get("requires_unpacking")),
            "detected_packers": list(triage.get("detected_packers", [])),
            "handoffs": handoffs,
            "next_actions": [
                "Execute the generated x64dbg/Frida plan in an isolated authorized sandbox.",
                "Feed captured key, IV, plaintext, and dump artifacts back into the pipeline.",
            ],
        }

    def _step_triage(self) -> dict[str, Any]:
        data = self.sample_path.read_bytes()
        binary_type = detect_binary_type(self.sample_path)
        strings = extract_strings(data)
        imports = extract_imports(data)
        packers = detect_packers(data, self._probable_section_names(strings))
        compiler = detect_compiler_language(data, imports, strings)
        triage_tool = "triage_pe" if binary_type == "pe" else "rizin_bin_info"
        triage_arguments = {"path": str(self.sample_path)}
        if binary_type == "pe":
            triage_arguments["write_markdown"] = True
        triage_handoff = self._external_handoff(
            "reverse_lab_tools",
            triage_tool,
            triage_arguments,
            "Run authoritative binary-format triage and return structured metadata.",
        )
        die_handoff = self._external_handoff(
            "reverse_lab_tools",
            "die_scan",
            {
                "path": str(self.sample_path),
                "deep": True,
                "heuristic": True,
                "entropy": True,
            },
            "Confirm packer, protector, compiler, and entropy signatures with Detect It Easy.",
        )
        backend_triage = triage_handoff.get("result", {})
        backend_die = die_handoff.get("result", {})
        backend_packers = []
        if isinstance(backend_die, Mapping):
            detected = backend_die.get("detected", [])
            if isinstance(detected, str):
                detected = [detected]
            backend_packers.extend(str(item) for item in detected if item)
            backend_text = json.dumps(backend_die, ensure_ascii=False, default=str)
            backend_packers.extend(
                name for name in _PACKER_MARKERS if name.lower() in backend_text.lower()
            )
        if backend_packers:
            packers = detect_packers(data, [*packers["detected"], *backend_packers])
        result = {
            "binary_type": binary_type,
            "size": len(data),
            "hashes": compute_hashes(self.sample_path),
            "entropy": round(_shannon_entropy(data), 3),
            "header_hex": data[:64].hex(),
            "packers": packers,
            "detected_packers": packers["detected"],
            "requires_unpacking": packers["requires_unpacking"],
            "compiler_language": compiler,
            "backend": {
                triage_tool: backend_triage,
                "die_scan": backend_die,
            },
            "handoffs": [triage_handoff, die_handoff],
        }
        if isinstance(backend_triage, Mapping) and isinstance(backend_triage.get("hashes"), Mapping):
            result["backend_hashes"] = dict(backend_triage["hashes"])
        return result

    @staticmethod
    def _probable_section_names(strings: Sequence[Mapping[str, Any]]) -> list[str]:
        names = []
        for item in strings:
            value = str(item.get("value", ""))
            if re.fullmatch(r"\.[A-Za-z0-9_$]{2,8}", value):
                names.append(value)
        return names

    def _step_static(self) -> dict[str, Any]:
        data = self.sample_path.read_bytes()
        local_strings = extract_strings(data)
        local_imports = extract_imports(data)
        descriptor = self._external_handoff(
            "reverse_lab_tools",
            "ghidra_headless_analyze",
            {
                "path": str(self.sample_path),
                "project_name": self.pipeline_id,
                "overwrite": True,
                "analysis_timeout_seconds": 600,
                "process_timeout_seconds": 1800,
                "function_limit": 500,
                "string_limit": 600,
                "import_limit": 500,
            },
            "Import and analyze the sample with Ghidra headless, exporting functions, xrefs, imports, strings, and decompilation.",
        )
        backend = descriptor.get("result", {})
        summary = backend.get("summary", {}) if isinstance(backend, Mapping) else {}
        if not isinstance(summary, Mapping):
            summary = {}
        imports = [
            dict(item)
            for item in summary.get("imports", [])
            if isinstance(item, Mapping)
        ] or local_imports
        strings = [
            dict(item)
            for item in summary.get("strings", [])
            if isinstance(item, Mapping)
        ] or local_strings
        for item in imports:
            if not item.get("function"):
                xrefs = item.get("xrefs", [])
                if isinstance(xrefs, Sequence) and xrefs and isinstance(xrefs[0], Mapping):
                    item["function"] = xrefs[0].get("function", xrefs[0].get("name", ""))
        for item in strings:
            if not item.get("function"):
                xrefs = item.get("xrefs", [])
                if isinstance(xrefs, Sequence) and xrefs and isinstance(xrefs[0], Mapping):
                    item["function"] = xrefs[0].get("function", xrefs[0].get("name", ""))
        functions = [
            dict(item)
            for item in summary.get("functions", [])
            if isinstance(item, Mapping)
        ]
        call_graph = {
            str(item.get("name", item.get("entry", ""))): [
                str(callee.get("name", callee.get("entry", "")))
                if isinstance(callee, Mapping)
                else str(callee)
                for callee in item.get("callees", [])
            ]
            for item in functions
            if item.get("name") or item.get("entry")
        }
        program = summary.get("program", {}) if isinstance(summary.get("program"), Mapping) else {}
        api_comments = {
            "crypto": "crypto operation",
            "network": "network operation",
            "anti_debug": "anti-debug check",
            "persistence": "persistence operation",
            "file": "file operation",
            "process": "process operation",
            "registry": "registry operation",
        }
        api_annotations = {}
        for item in imports:
            name = str(item.get("name", ""))
            category = _import_category(name)
            if name and category in api_comments:
                api_annotations[name] = api_comments[category]
                item["annotation"] = api_comments[category]
        return {
            "_step_status": "completed" if descriptor.get("status") == "completed" else "awaiting-external",
            "strings": strings,
            "string_groups": group_strings(strings),
            "imports": imports,
            "import_groups": group_imports(imports),
            "exports": [
                dict(item)
                for item in summary.get("exports", program.get("exports", []))
                if isinstance(item, Mapping)
            ],
            "entry_point": program.get("entry_point", program.get("entry", "")),
            "functions": functions,
            "call_graph": call_graph,
            "api_annotations": api_annotations,
            "compiler_language": detect_compiler_language(data, imports, strings),
            "ghidra": {
                "summary_path": backend.get("summary_path", "") if isinstance(backend, Mapping) else "",
                "status": descriptor.get("status", "pending"),
            },
            "handoff": descriptor,
        }

    def _step_identify(self) -> dict[str, Any]:
        static = self.state["results"].get("static", {})
        findings = identify_key_functions(
            static.get("imports", []),
            static.get("strings", []),
            static.get("call_graph", {}),
        )
        return {
            "key_functions": findings,
            "categories": sorted({item["category"] for item in findings}),
        }

    def _step_plan(self) -> dict[str, Any]:
        triage = self.state["results"].get("triage", {})
        static = self.state["results"].get("static", {})
        binary_type = triage.get("binary_type", "unknown")
        x64dbg_path = ""
        if binary_type == "pe":
            x64dbg_path = self._write_artifact(
                "x64dbg_script",
                "scripts/x64dbg_breakpoints.txt",
                self._render_x64dbg_script(static.get("imports", [])),
            )
        frida_path = self._write_artifact(
            "frida_script",
            "scripts/frida_hooks.js",
            self._render_frida_script(static.get("imports", []), binary_type),
        )
        decrypt_plan = self.decrypt_plan()
        unpack_plan_path = decrypt_plan["path"]
        self.state["next_actions"] = list(
            dict.fromkeys(
                [
                    *self.state.get("next_actions", []),
                    *decrypt_plan.get("next_actions", []),
                ]
            )
        )
        summary_path = static.get("ghidra", {}).get("summary_path", "")
        api_names = ",".join(
            str(item.get("name", ""))
            for item in static.get("imports", [])
            if item.get("annotation")
        )
        handoffs = []
        if binary_type == "pe":
            handoffs.extend(
                [
                    self._external_handoff(
                        "reverse_lab_tools",
                        "make_x64dbg_breakpoint_script",
                        {
                            "sample_path": str(self.sample_path),
                            "summary_path": summary_path,
                            "output_path": str(self.output_dir / "external" / "x64dbg-breakpoints.txt"),
                            "api_names": api_names,
                            "function_limit": 20,
                        },
                        "Generate debugger-native API and key-function breakpoints from the Ghidra summary.",
                        execute=False,
                    ),
                    self._external_handoff(
                        "reverse_lab_tools",
                        "make_pe_crypto_unpack_plan",
                        {
                            "sample_path": str(self.sample_path),
                            "summary_path": summary_path,
                            "mode": "both",
                            "output_path": str(self.output_dir / "external" / "pe-crypto-unpack-plan.json"),
                            "include_frida": True,
                            "focus_limit": 20,
                        },
                        "Generate an x64dbg and Windows Frida package for crypto tracing and unpacking.",
                        execute=False,
                    ),
                    self._external_handoff(
                        "reverse_lab_tools",
                        "make_procmon_filters",
                        {
                            "sample_path": str(self.sample_path),
                            "summary_path": summary_path,
                            "output_path": str(self.output_dir / "external" / "procmon-filters.pmc"),
                            "include_noise_excludes": True,
                        },
                        "Generate Procmon filters for file, process, registry, and persistence evidence.",
                        execute=False,
                    ),
                ]
            )
        result = {
            "frida_script": frida_path,
            "decrypt_unpack_plan": unpack_plan_path,
            "handoff_ids": [item["handoff_id"] for item in handoffs],
            "handoffs": handoffs,
        }
        if x64dbg_path:
            result["x64dbg_script"] = x64dbg_path
        return result

    def _step_capture(self) -> dict[str, Any]:
        script_path = self.state["artifacts"].get("frida_script", "")
        script_source = (
            Path(script_path).read_text(encoding="utf-8")
            if script_path and Path(script_path).is_file()
            else self._render_frida_script(
                self.state["results"].get("static", {}).get("imports", []),
                self.state["results"].get("triage", {}).get("binary_type", "unknown"),
            )
        )
        descriptor = self._external_handoff(
            "frida",
            "run_script",
            {
                "target": str(self.sample_path),
                "script_source": script_source,
                "mode": "spawn",
                "duration_seconds": 30,
                "output_path": str(self.output_dir / "captures" / "dynamic-capture.json"),
            },
            "Capture runtime arguments, return values, plaintext, endpoints, and anti-debug behavior.",
        )
        if self.backend_runner is None or descriptor.get("status") != "completed":
            return {
                "_step_status": "awaiting-external",
                "handoff": descriptor,
                "message": "Dynamic capture requires an external backend runner.",
            }
        return {
            "handoff": descriptor,
            "capture": descriptor.get("result"),
        }

    def _step_produce(self) -> dict[str, Any]:
        iocs = self.extract_iocs()
        rule_paths = self.generate_rules()
        crypto_records = self._captured_crypto_records(
            self.state["results"].get("capture", {})
        )
        decrypt_script = ""
        if crypto_records:
            decrypt_script = self._write_artifact(
                "decrypt_script",
                "scripts/decrypt_capture.py",
                self._render_decrypt_script(crypto_records[0]),
            )
        markdown_path = self._write_artifact(
            "report_markdown",
            "reports/reverse-report.md",
            self._render_markdown_report(iocs),
        )
        report_snapshot = json.loads(json.dumps(self.state, default=str))
        report_snapshot["ioc_summary"] = iocs
        json_path = self._write_artifact(
            "report_json",
            "reports/reverse-report.json",
            report_snapshot,
        )
        result = {
            "report_markdown": markdown_path,
            "report_json": json_path,
            **rule_paths,
        }
        if decrypt_script:
            result["decrypt_script"] = decrypt_script
        return result

    @classmethod
    def _captured_crypto_records(cls, value: Any) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        if isinstance(value, Mapping):
            if value.get("algorithm") and any(
                value.get(key)
                for key in ("key", "key_hex", "iv", "iv_hex", "salt")
            ):
                records.append(dict(value))
            for child in value.values():
                records.extend(cls._captured_crypto_records(child))
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value:
                records.extend(cls._captured_crypto_records(child))
        unique = {}
        for record in records:
            unique[json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)] = record
        return list(unique.values())

    @staticmethod
    def _render_decrypt_script(record: Mapping[str, Any]) -> str:
        algorithm = str(record.get("algorithm", "unknown")).lower()
        key_hex = str(record.get("key_hex", ""))
        iv_hex = str(record.get("iv_hex", ""))
        salt = str(record.get("salt", ""))
        return "\n".join(
            [
                '"""Generated from authorized dynamic crypto-capture evidence."""',
                "",
                "import base64",
                "",
                f'ALGORITHM = {json.dumps(algorithm)}',
                f'KEY = bytes.fromhex({json.dumps(key_hex)})',
                f'IV = bytes.fromhex({json.dumps(iv_hex)})',
                f'SALT = {json.dumps(salt)}',
                "",
                "def decrypt(data: bytes) -> bytes:",
                "    if ALGORITHM in {'xor', 'xor-stream'}:",
                "        if not KEY:",
                "            raise ValueError('captured XOR key is empty')",
                "        return bytes(value ^ KEY[index % len(KEY)] for index, value in enumerate(data))",
                "    if ALGORITHM in {'base64', 'b64'}:",
                "        return base64.b64decode(data)",
                "    raise NotImplementedError(",
                "        f'Implement {ALGORITHM} with the captured KEY/IV using the approved crypto backend.'",
                "    )",
                "",
                "if __name__ == '__main__':",
                "    raise SystemExit('Import decrypt() and pass the captured ciphertext bytes.')",
                "",
            ]
        )

    def _render_x64dbg_script(self, imports: Sequence[Mapping[str, Any]]) -> str:
        preferred = [
            str(item.get("name", ""))
            for item in imports
            if _import_category(str(item.get("name", "")))
            in {"crypto", "network", "anti_debug", "persistence", "file", "process", "registry"}
        ]
        defaults = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "CryptEncrypt",
            "CryptDecrypt",
            "WinHttpSendRequest",
            "HttpSendRequestW",
            "CreateFileW",
            "WriteFile",
            "DeleteFileW",
            "CreateProcessW",
            "WriteProcessMemory",
            "RegSetValueExW",
        ]
        names = list(dict.fromkeys(preferred + defaults))
        lines = [
            "// Hunter binary reverse pipeline x64dbg breakpoints",
            f"// Sample: {self.sample_path}",
        ]
        for finding in self.state["results"].get("identify", {}).get("key_functions", []):
            function_name = str(finding.get("function", ""))
            if function_name and function_name not in names:
                lines.append(f"// key function: {finding.get('category', 'unknown')} {function_name}")
                lines.append(f"bp {function_name}")
        lines.extend(f"bp {name}" for name in names)
        lines.append("run")
        return "\n".join(lines) + "\n"

    def _render_frida_script(
        self,
        imports: Sequence[Mapping[str, Any]],
        binary_type: str = "pe",
    ) -> str:
        names = [
            str(item.get("name", ""))
            for item in imports
            if _import_category(str(item.get("name", "")))
            in {"crypto", "network", "anti_debug", "persistence", "file", "process", "registry"}
        ]
        platform_defaults = (
            [
                    "CryptEncrypt",
                    "CryptDecrypt",
                    "WinHttpSendRequest",
                    "HttpSendRequestW",
                    "CreateFileW",
                    "WriteFile",
                    "DeleteFileW",
                    "CreateProcessW",
                    "WriteProcessMemory",
                    "IsDebuggerPresent",
                    "RegSetValueExW",
                ]
            if binary_type == "pe"
            else [
                "connect",
                "send",
                "recv",
                "open",
                "read",
                "write",
                "dlopen",
                "mmap",
                "mprotect",
            ]
        )
        names = list(dict.fromkeys(names + platform_defaults))
        encoded_names = json.dumps(names)
        return (
            "'use strict';\n"
            f"const targets = {encoded_names};\n"
            "function hookExport(name) {\n"
            "  const address = Module.findGlobalExportByName(name);\n"
            "  if (address === null) return;\n"
            "  Interceptor.attach(address, {\n"
            "    onEnter(args) {\n"
            "      this.name = name;\n"
            "      send({event: 'enter', api: name, arg0: args[0].toString(), arg1: args[1].toString()});\n"
            "    },\n"
            "    onLeave(retval) {\n"
            "      send({event: 'leave', api: this.name, retval: retval.toString()});\n"
            "    }\n"
            "  });\n"
            "}\n"
            "setImmediate(() => targets.forEach(hookExport));\n"
        )

    def _render_unpack_plan(self, triage: Mapping[str, Any]) -> str:
        packers = triage.get("detected_packers", [])
        compiler = triage.get("compiler_language", {})
        lines = [
            "# Decrypt and Unpack Plan",
            "",
            f"- Sample: `{self.sample_path.name}`",
            f"- Type: `{triage.get('binary_type', 'unknown')}`",
            f"- Packers: `{', '.join(packers) if packers else 'none detected'}`",
            f"- Compiler/language: `{compiler.get('compiler') or compiler.get('language') or 'unknown'}`",
            "",
            "## Sequence",
            "",
        ]
        if triage.get("requires_unpacking"):
            lines.extend(
                [
                    "1. Confirm the protector with ReverseLabTools/DIE-style inspection.",
                    "2. Prefer the packer-native unpack path when available; otherwise break at the original entry point.",
                    "3. Dump the reconstructed image after code and imports are restored.",
                    "4. Rebuild imports, verify hashes, and rerun static identification on the dump.",
                ]
            )
        else:
            lines.extend(
                [
                    "1. Validate entropy and section layout before assuming the sample is unpacked.",
                    "2. Trace crypto API arguments and buffers with the generated Frida/x64dbg scripts.",
                    "3. Extract keys, IVs, plaintext, and configuration with repeatable input/output captures.",
                    "4. Feed captured artifacts back into Ghidra for xref and call-graph refinement.",
                ]
            )
        lines.extend(
            [
                "",
                "## Evidence to Preserve",
                "",
                "- Original and dumped-image hashes",
                "- Original entry point and resolved import table",
                "- Crypto keys, IVs, plaintext buffers, and configuration blobs",
                "- Network endpoints, request bodies, and timing",
            ]
        )
        return "\n".join(lines) + "\n"

    def _build_iocs(self) -> dict[str, Any]:
        triage = self.state["results"].get("triage", {})
        static = self.state["results"].get("static", {})
        groups = static.get("string_groups", {})
        static_urls = {
            str(item.get("value", ""))
            for item in groups.get("urls", [])
            if item.get("value")
        }
        static_domains = {
            str(item.get("value", ""))
            for item in groups.get("domains", [])
            if item.get("value")
        }
        static_ips = {
            str(item.get("value", ""))
            for item in groups.get("ip_addresses", [])
            if item.get("value")
        }
        static_paths = {
            str(item.get("value", ""))
            for item in groups.get("paths", [])
            if item.get("value")
        }
        static_registry = {
            str(item.get("value", ""))
            for category in ("registry", "persistence")
            for item in groups.get(category, [])
            if item.get("value")
        }
        for url in static_urls:
            match = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
            if not match:
                continue
            host = match.group(1)
            try:
                ipaddress.ip_address(host)
                static_ips.add(host)
            except ValueError:
                static_domains.add(host.lower())
        capture_result = self.state["results"].get("capture", {})
        capture_step = self._step_record("capture")
        capture_evidence = {}
        if capture_step.get("status") == "completed" and isinstance(capture_result, Mapping):
            capture_evidence = (
                capture_result.get("capture")
                or capture_result.get("captures")
                or {}
            )
        capture_text = json.dumps(
            capture_evidence,
            ensure_ascii=False,
            default=str,
        )
        dynamic_urls = set(re.findall(r"https?://[^\s\"'<>]+", capture_text))
        dynamic_domains = set()
        dynamic_ips = set()
        for url in dynamic_urls:
            match = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
            if match:
                dynamic_domains.add(match.group(1).lower())
        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", capture_text):
            try:
                dynamic_ips.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        dynamic_paths = set(
            re.findall(r"(?:[A-Za-z]:\\[^\"'\r\n]+|/(?:tmp|var|etc|home|opt)/[^\"'\r\n]+)", capture_text)
        )
        dynamic_registry = set(
            re.findall(
                r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\"'\r\n]+",
                capture_text,
                re.IGNORECASE,
            )
        )
        combined = {
            "urls": sorted(static_urls | dynamic_urls),
            "domains": sorted(static_domains | dynamic_domains),
            "ip_addresses": sorted(static_ips | dynamic_ips),
            "paths": sorted(static_paths | dynamic_paths),
            "registry": sorted(static_registry | dynamic_registry),
        }
        static_sets = {
            "urls": static_urls,
            "domains": static_domains,
            "ip_addresses": static_ips,
            "paths": static_paths,
            "registry": static_registry,
        }
        dynamic_sets = {
            "urls": dynamic_urls,
            "domains": dynamic_domains,
            "ip_addresses": dynamic_ips,
            "paths": dynamic_paths,
            "registry": dynamic_registry,
        }
        sources = {
            category: [
                {
                    "value": value,
                    "sources": [
                        source
                        for source, values in (
                            ("static", static_sets[category]),
                            ("dynamic", dynamic_sets[category]),
                        )
                        if value in values
                    ],
                }
                for value in combined[category]
            ]
            for category in combined
        }
        return {
            "sample": self.sample_path.name,
            "hashes": triage.get("hashes", compute_hashes(self.sample_path)),
            **combined,
            "sources": sources,
            "dynamic_capture_present": bool(capture_evidence),
            "generated_at": _utc_now(),
        }

    @staticmethod
    def _yara_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    def _render_yara(self, iocs: Mapping[str, Any]) -> str:
        rule_name = re.sub(r"[^A-Za-z0-9_]", "_", self.sample_path.stem)
        if not rule_name or rule_name[0].isdigit():
            rule_name = f"sample_{rule_name}"
        rule_name = rule_name[:120]
        high_signal_apis = {
            "CryptEncrypt",
            "CryptDecrypt",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "RegSetValueExW",
            "IsDebuggerPresent",
            "NtQueryInformationProcess",
        }
        candidates = (
            list(iocs.get("urls", []))
            + list(iocs.get("domains", []))
            + list(iocs.get("registry", []))
            + list(iocs.get("paths", []))
            + [
                item.get("name", "")
                for item in self.state["results"].get("static", {}).get("imports", [])
                if item.get("name") in high_signal_apis
            ]
        )
        candidates = [str(value) for value in dict.fromkeys(candidates) if len(str(value)) >= 4]
        strings = [
            f'        $s{index} = "{self._yara_escape(value)}" ascii wide'
            for index, value in enumerate(candidates[:16], start=1)
        ]
        condition = f'hash.sha256(0, filesize) == "{iocs["hashes"]["sha256"]}"'
        return "\n".join(
            [
                "import \"hash\"",
                "",
                f"rule Hunter_{rule_name} {{",
                "    meta:",
                f'        description = "Hunter reverse pipeline signature for {self._yara_escape(self.sample_path.name)}"',
                f'        sha256 = "{iocs["hashes"]["sha256"]}"',
                '        candidate_strings = "Analyst refinement only; not used in the automatic condition"',
                "    strings:",
                *(strings or ['        $fallback = "Hunter reverse pipeline"']),
                "    condition:",
                f"        {condition}",
                "}",
                "",
            ]
        )

    def _render_sigma(self, iocs: Mapping[str, Any]) -> str:
        title = self.sample_path.name.replace('"', "'")
        sha256 = iocs["hashes"]["sha256"]
        documents = [
            "\n".join(
                [
                    f"title: Hunter Binary Execution - {title}",
                    f"id: {uuid.uuid5(uuid.NAMESPACE_URL, sha256 + ':process')}",
                    "status: experimental",
                    "description: Detects execution of the analyzed binary by image name or SHA256.",
                    "logsource:",
                    "  category: process_creation",
                    "detection:",
                    "  selection_image:",
                    f"    Image|endswith: {json.dumps(chr(92) + self.sample_path.name)}",
                    "  selection_hash:",
                    f"    Hashes|contains: {json.dumps('SHA256=' + sha256)}",
                    "  condition: selection_hash",
                    "level: medium",
                    "tags:",
                    "  - attack.execution",
                ]
            )
        ]
        if iocs.get("registry"):
            registry_values = "\n".join(
                f"      - {json.dumps(value)}" for value in iocs["registry"][:12]
            )
            documents.append(
                "\n".join(
                    [
                        f"title: Hunter Registry Behavior - {title}",
                        f"id: {uuid.uuid5(uuid.NAMESPACE_URL, sha256 + ':registry')}",
                        "status: experimental",
                        "logsource:",
                        "  category: registry_set",
                        "detection:",
                        "  selection:",
                        "    TargetObject|contains:",
                        registry_values,
                        "  condition: selection",
                        "level: high",
                        "tags:",
                        "  - attack.persistence",
                    ]
                )
            )
        domains = list(iocs.get("domains", []))
        ip_values = list(iocs.get("ip_addresses", []))
        if domains or ip_values:
            network_lines = []
            conditions = []
            if domains:
                network_lines.extend(
                    [
                        "  selection_hostname:",
                        "    DestinationHostname|contains:",
                        *[f"      - {json.dumps(value)}" for value in domains[:20]],
                    ]
                )
                conditions.append("selection_hostname")
            if ip_values:
                network_lines.extend(
                    [
                        "  selection_ip:",
                        "    DestinationIp:",
                        *[f"      - {json.dumps(value)}" for value in ip_values[:20]],
                    ]
                )
                conditions.append("selection_ip")
            documents.append(
                "\n".join(
                    [
                        f"title: Hunter Network Behavior - {title}",
                        f"id: {uuid.uuid5(uuid.NAMESPACE_URL, sha256 + ':network')}",
                        "status: experimental",
                        "logsource:",
                        "  category: network_connection",
                        "detection:",
                        *network_lines,
                        f"  condition: {' or '.join(conditions)}",
                        "level: high",
                        "tags:",
                        "  - attack.command-and-control",
                    ]
                )
            )
        return "\n---\n".join(documents) + "\n"

    def _render_markdown_report(self, iocs: Mapping[str, Any]) -> str:
        triage = self.state["results"].get("triage", {})
        identify = self.state["results"].get("identify", {})
        packers = ", ".join(triage.get("detected_packers", [])) or "None detected"
        lines = [
            "# Binary Reverse Engineering Report",
            "",
            "## Sample",
            "",
            f"- Path: `{self.sample_path}`",
            f"- Type: `{triage.get('binary_type', 'unknown')}`",
            f"- Size: `{triage.get('size', 0)}` bytes",
            f"- MD5: `{iocs['hashes']['md5']}`",
            f"- SHA1: `{iocs['hashes']['sha1']}`",
            f"- SHA256: `{iocs['hashes']['sha256']}`",
            f"- Packers: `{packers}`",
            f"- Requires unpacking: `{triage.get('requires_unpacking', False)}`",
            "",
            "## Key Functions",
            "",
        ]
        findings = identify.get("key_functions", [])
        if findings:
            for finding in findings:
                evidence = finding.get("evidence", finding.get("reasons", []))
                lines.append(
                    f"- **{finding['category']}** `{finding['function']}` "
                    f"(confidence {finding['confidence']:.2f}): "
                    + "; ".join(str(item) for item in evidence)
                )
        else:
            lines.append("- No key functions identified by local heuristics.")
        lines.extend(
            [
                "",
                "## IOCs",
                "",
                f"- URLs: `{', '.join(iocs['urls']) or 'none'}`",
                f"- Domains: `{', '.join(iocs['domains']) or 'none'}`",
                f"- IP addresses: `{', '.join(iocs['ip_addresses']) or 'none'}`",
                "",
                "## External Handoffs",
                "",
            ]
        )
        for descriptor in self.state.get("handoffs", []):
            lines.append(
                f"- `{descriptor['server']}.{descriptor['tool']}`: "
                f"{descriptor['purpose']} (`{descriptor['status']}`)"
            )
        lines.extend(
            [
                "",
                "## Dynamic Capture",
                "",
                f"- Status: `{self._step_record('capture')['status']}`",
                "- Awaiting-external means no runtime claim was made without an injected backend.",
                "",
            ]
        )
        return "\n".join(lines)
