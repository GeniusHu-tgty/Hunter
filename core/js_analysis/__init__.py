"""Static JavaScript bundle analysis primitives."""

from .bundle_unpacker import detect_bundler, unpack_bundle
from .deobfuscator import deobfuscate

__all__ = ["detect_bundler", "unpack_bundle", "deobfuscate"]
