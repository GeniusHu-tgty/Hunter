from __future__ import annotations
from copy import deepcopy


class BackendRegistry:
    def __init__(self, backends=None):
        self.backends = backends or {}

    @classmethod
    def default(cls):
        common_reverse = {"server": "reverse_lab_tools", "execution": "external-mcp"}
        return cls({
            "web": [{"server": "hunter_tools", "execution": "native", "capabilities": ["hunter_fast_scan", "hunter_scan_plan", "hunter_auto_access_control"]}],
            "api": [{"server": "hunter_tools", "execution": "native", "capabilities": ["hunter_fast_scan", "hunter_auto_graphql", "hunter_auto_idor"]}],
            "source": [{"server": "hunter_tools", "execution": "native", "capabilities": ["hunter_js_analyze", "hunter_kb_recommend"]}],
            "pe": [{**common_reverse, "capabilities": ["triage_pe", "die_scan", "ghidra_headless_analyze", "sample_full_workup"]}, {"server": "ghidra", "execution": "external-mcp", "capabilities": ["decompile_function", "get_function_xrefs"]}],
            "pwn": [{**common_reverse, "capabilities": ["triage_pe", "rizin_bin_info", "ghidra_headless_analyze", "make_x64dbg_breakpoint_script"]}, {"server": "ghidra", "execution": "external-mcp", "capabilities": ["decompile_function", "disassemble_function"]}],
            "apk": [{**common_reverse, "capabilities": ["android_app_baseline", "android_package_info", "android_http_observation_recipe", "android_crypto_unpack_recipe"]}],
            "javascript": [{"server": "jshook", "execution": "external-mcp", "capabilities": ["collect_code", "search_in_scripts", "extract_function_tree", "manage_hooks"]}],
            "firmware": [{**common_reverse, "capabilities": ["hash_file", "die_scan", "carve_payloads_from_dump", "sample_full_workup"]}],
            "script": [{"server": "jshook", "execution": "external-mcp", "capabilities": ["detect_obfuscation", "advanced_deobfuscate", "detect_crypto", "understand_code"]}],
            "document": [{**common_reverse, "capabilities": ["hash_file", "die_scan", "sample_full_workup"]}],
            "protocol": [{**common_reverse, "capabilities": ["http_probe", "kb_router", "kb_read_file"]}],
            "capture": [{**common_reverse, "capabilities": ["hash_file", "kb_router", "kb_read_file"]}],
            "crypto": [{**common_reverse, "capabilities": ["solve_crypto_from_evidence", "make_crypto_replay_scaffold", "postprocess_frida_crypto_result"]}],
        })

    def resolve(self, lane):
        if lane == "mixed":
            out = []
            seen = set()
            for child in self.backends:
                for item in self.backends.get(child, []):
                    key = item["server"]
                    if key in seen:
                        existing = next(x for x in out if x["server"] == key)
                        existing["capabilities"] = sorted(set(existing["capabilities"]) | set(item["capabilities"]))
                    else:
                        out.append(deepcopy(item)); seen.add(key)
            return out
        return deepcopy(self.backends.get(lane, self.backends.get("web", [])))

    def status(self):
        return {"backends": deepcopy(self.backends), "lanes": sorted([*self.backends, "mixed"]), "contract": "capability-descriptor-v1"}
