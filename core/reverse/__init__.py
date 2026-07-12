"""Binary reverse-engineering pipeline primitives."""

from .binary_pipeline import (
    BinaryPipeline,
    calculate_hashes,
    compute_hashes,
    detect_binary_type,
    detect_binary_type_details,
    detect_compiler,
    detect_compiler_language,
    detect_packers,
    extract_imports,
    extract_strings,
    group_imports,
    group_strings,
    identify_key_functions,
    semantic_group_imports,
    semantic_group_strings,
)
from .android_pipeline import AndroidPipeline, generate_android_frida_hooks, parse_android_manifest

__all__ = [
    "BinaryPipeline",
    "calculate_hashes",
    "compute_hashes",
    "detect_binary_type",
    "detect_binary_type_details",
    "detect_compiler",
    "detect_compiler_language",
    "detect_packers",
    "extract_imports",
    "extract_strings",
    "group_imports",
    "group_strings",
    "identify_key_functions",
    "semantic_group_imports",
    "semantic_group_strings",
    "AndroidPipeline",
    "generate_android_frida_hooks",
    "parse_android_manifest",
]
