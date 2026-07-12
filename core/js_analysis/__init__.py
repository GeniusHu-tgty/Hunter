"""Static JavaScript bundle analysis primitives."""

from .bundle_unpacker import detect_bundler, unpack_bundle
from .deobfuscator import deobfuscate
from .api_extractor import extract_api
from .signature_extractor import analyze_signature, extract_signature, extract_signatures

__all__ = [
    "detect_bundler",
    "unpack_bundle",
    "deobfuscate",
    "extract_api",
    "extract_signature",
    "extract_signatures",
    "analyze_signature",
]
