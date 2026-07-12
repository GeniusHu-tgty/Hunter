from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .binary_pipeline import BinaryPipeline


ANDROID_NAMESPACE = "{http://schemas.android.com/apk/res/android}"


def _android_attribute(element: ElementTree.Element, name: str, default: str = "") -> str:
    return element.attrib.get(f"{ANDROID_NAMESPACE}{name}", element.attrib.get(f"android:{name}", default))


def _component_name(package: str, name: str) -> str:
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def parse_android_manifest(content: bytes | str) -> dict[str, Any]:
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    if not text.lstrip().startswith("<"):
        return {
            "decoded": False,
            "package": "",
            "permissions": [],
            "components": [],
            "exported_components": [],
            "intent_filters": [],
            "application": "",
        }
    root = ElementTree.fromstring(text)
    package = root.attrib.get("package", "")
    permissions = sorted(
        {
            _android_attribute(item, "name")
            for item in root.findall("uses-permission")
            if _android_attribute(item, "name")
        }
    )
    application = root.find("application")
    application_name = _android_attribute(application, "name") if application is not None else ""
    components: list[dict[str, Any]] = []
    intent_filters: list[dict[str, Any]] = []
    exported_components: list[dict[str, Any]] = []
    if application is not None:
        for component_type in ("activity", "activity-alias", "service", "receiver", "provider"):
            for element in application.findall(component_type):
                raw_name = _android_attribute(element, "name")
                filters = []
                for intent_filter in element.findall("intent-filter"):
                    actions = [
                        _android_attribute(item, "name")
                        for item in intent_filter.findall("action")
                        if _android_attribute(item, "name")
                    ]
                    categories = [
                        _android_attribute(item, "name")
                        for item in intent_filter.findall("category")
                        if _android_attribute(item, "name")
                    ]
                    data = [
                        {
                            key: _android_attribute(item, key)
                            for key in ("scheme", "host", "port", "path", "pathPrefix", "mimeType")
                            if _android_attribute(item, key)
                        }
                        for item in intent_filter.findall("data")
                    ]
                    filters.append({"actions": actions, "categories": categories, "data": data})
                explicit_exported = _android_attribute(element, "exported")
                exported = explicit_exported.lower() == "true" if explicit_exported else bool(filters)
                record = {
                    "type": component_type,
                    "name": raw_name,
                    "qualified_name": _component_name(package, raw_name),
                    "exported": exported,
                    "permission": _android_attribute(element, "permission"),
                    "intent_filters": filters,
                }
                components.append(record)
                if exported:
                    exported_components.append(record)
                for intent_filter in filters:
                    intent_filters.append(
                        {
                            "component": raw_name,
                            "component_type": component_type,
                            **intent_filter,
                        }
                    )
    return {
        "decoded": True,
        "package": package,
        "permissions": permissions,
        "components": components,
        "exported_components": exported_components,
        "intent_filters": intent_filters,
        "application": application_name,
    }


def generate_android_frida_hooks() -> str:
    return r"""'use strict';

function bytesToHex(value) {
  if (!value) return null;
  try {
    var result = [];
    for (var index = 0; index < value.length; index++) {
      result.push(('0' + (value[index] & 0xff).toString(16)).slice(-2));
    }
    return result.join('');
  } catch (error) {
    return '<unavailable:' + error + '>';
  }
}

Java.perform(function () {
  function emit(kind, payload) {
    send({source: 'hunter_reverse_android', kind: kind, payload: payload});
  }

  try {
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    var build = RequestBuilder.build.overload();
    build.implementation = function () {
      var request = build.call(this);
      emit('okhttp_request', {
        method: String(request.method()),
        url: String(request.url()),
        headers: String(request.headers())
      });
      return request;
    };
  } catch (error) {
    emit('hook_unavailable', {target: 'okhttp3.Request$Builder.build', error: String(error)});
  }

  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        emit('cipher_init', {
          algorithm: String(this.getAlgorithm()),
          mode: arguments.length ? String(arguments[0]) : '',
          key: arguments.length > 1 && arguments[1] && arguments[1].getEncoded
            ? bytesToHex(arguments[1].getEncoded()) : null
        });
        return result;
      };
    });
    Cipher.doFinal.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var input = arguments.length && arguments[0] ? bytesToHex(arguments[0]) : null;
        var output = overload.apply(this, arguments);
        emit('cipher_do_final', {
          algorithm: String(this.getAlgorithm()),
          input: input,
          output: bytesToHex(output)
        });
        return output;
      };
    });
  } catch (error) {
    emit('hook_unavailable', {target: 'javax.crypto.Cipher', error: String(error)});
  }

  try {
    var WebView = Java.use('android.webkit.WebView');
    var addJavascriptInterface = WebView.addJavascriptInterface.overload(
      'java.lang.Object',
      'java.lang.String'
    );
    addJavascriptInterface.implementation = function (object, name) {
      emit('webview_js_bridge', {name: String(name), object_class: String(object.getClass().getName())});
      return addJavascriptInterface.call(this, object, name);
    };
    var loadUrl = WebView.loadUrl.overload('java.lang.String');
    loadUrl.implementation = function (url) {
      emit('webview_load_url', {url: String(url)});
      return loadUrl.call(this, url);
    };
  } catch (error) {
    emit('hook_unavailable', {target: 'android.webkit.WebView', error: String(error)});
  }

  try {
    var Base64 = Java.use('android.util.Base64');
    Base64.encode.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var output = overload.apply(this, arguments);
        emit('base64_encode', {
          input: arguments.length ? bytesToHex(arguments[0]) : null,
          output: bytesToHex(output)
        });
        return output;
      };
    });
    Base64.decode.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var output = overload.apply(this, arguments);
        emit('base64_decode', {output: bytesToHex(output)});
        return output;
      };
    });
  } catch (error) {
    emit('hook_unavailable', {target: 'android.util.Base64', error: String(error)});
  }
});
"""


class AndroidPipeline(BinaryPipeline):
    STEPS = (
        "triage",
        "android_frontend",
        "dex_java",
        "native",
        "identify",
        "plan",
        "capture",
        "produce",
    )

    def __init__(self, sample_path: str | Path, **kwargs: Any) -> None:
        kwargs.pop("sample_type", None)
        super().__init__(sample_path, **kwargs)
        self.state["pipeline_kind"] = "android"
        self._persist_state()

    def _apk_entries(self) -> list[str]:
        with zipfile.ZipFile(self.sample_path) as archive:
            return archive.namelist()

    def _run_static_tool(self, executable: str, arguments: list[str], timeout: int = 300) -> dict[str, Any]:
        resolved = shutil.which(executable) or shutil.which(f"{executable}.bat") or shutil.which(f"{executable}.exe")
        if not resolved:
            return {"status": "unavailable", "tool": executable, "command": [executable, *arguments]}
        completed = subprocess.run(
            [resolved, *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "status": "completed" if completed.returncode == 0 else "error",
            "tool": executable,
            "command": [resolved, *arguments],
            "returncode": completed.returncode,
            "stdout": completed.stdout[-8000:],
            "stderr": completed.stderr[-8000:],
        }

    def _step_android_frontend(self) -> dict[str, Any]:
        with zipfile.ZipFile(self.sample_path) as archive:
            manifest_bytes = archive.read("AndroidManifest.xml")
        manifest_path = self.output_dir / "android" / "AndroidManifest.xml"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(manifest_bytes)
        result = parse_android_manifest(manifest_bytes)
        apktool_result = None
        if not result["decoded"]:
            decoded_root = self.output_dir / "android" / "apktool"
            apktool_result = self._run_static_tool(
                "apktool",
                ["d", "-f", str(self.sample_path), "-o", str(decoded_root)],
            )
            decoded_manifest = decoded_root / "AndroidManifest.xml"
            if apktool_result["status"] == "completed" and decoded_manifest.is_file():
                result = parse_android_manifest(decoded_manifest.read_text(encoding="utf-8", errors="replace"))
                result["decoded_manifest_path"] = str(decoded_manifest)
        result["manifest_path"] = str(manifest_path)
        result["apktool"] = apktool_result
        result["handoffs"] = []
        if not result["decoded"]:
            result["handoffs"].append(
                self._external_handoff(
                    "reverse_lab_tools",
                    "android_app_baseline",
                    {
                        "apk_path": str(self.sample_path),
                        "launch": False,
                        "reinstall": False,
                        "grant_permissions": False,
                    },
                    "Collect an Android baseline while preserving the APK; apktool is required locally to decode binary AXML.",
                )
            )
        if result["package"]:
            result["handoffs"].append(
                self._external_handoff(
                    "reverse_lab_tools",
                    "android_package_info",
                    {"package_name": result["package"]},
                    "Validate permissions, exported components, and intent filters on the authorized device.",
                )
            )
        return result

    def _step_dex_java(self) -> dict[str, Any]:
        class_markers = {
            "crypto": (
                "javax.crypto",
                "java.security",
                "Cipher",
                "SecretKeySpec",
                "MessageDigest",
            ),
            "network": (
                "okhttp3",
                "retrofit2",
                "HttpURLConnection",
                "java.net.Socket",
            ),
            "webview": (
                "android.webkit.WebView",
                "addJavascriptInterface",
                "WebViewClient",
            ),
            "dynamic_loading": (
                "DexClassLoader",
                "PathClassLoader",
                "System.loadLibrary",
            ),
        }
        matches: dict[str, list[Any]] = {category: [] for category in class_markers}
        dex_files = []
        jadx_root = self.output_dir / "android" / "jadx"
        jadx_result = self._run_static_tool(
            "jadx",
            ["--no-res", "-d", str(jadx_root), str(self.sample_path)],
        )
        if jadx_result["status"] == "completed":
            for java_path in jadx_root.rglob("*.java"):
                source = java_path.read_text(encoding="utf-8", errors="replace")
                for category, markers in class_markers.items():
                    for marker in markers:
                        if marker in source:
                            matches[category].append(
                                {
                                    "marker": marker,
                                    "path": str(java_path),
                                }
                            )
        with zipfile.ZipFile(self.sample_path) as archive:
            for name in archive.namelist():
                if not re.fullmatch(r"(?:.*/)?classes\d*\.dex", name):
                    continue
                payload = archive.read(name)
                text = payload.decode("latin-1", errors="ignore")
                dex_files.append({"path": name, "size": len(payload)})
                for category, markers in class_markers.items():
                    for marker in markers:
                        if marker in text and not any(
                            item == marker or (isinstance(item, dict) and item.get("marker") == marker)
                            for item in matches[category]
                        ):
                            matches[category].append(marker)
        return {
            "dex_files": dex_files,
            "matches": matches,
            "jadx": jadx_result,
            "handoffs": [
                self._external_handoff(
                    "local-toolchain",
                    "jadx",
                    {"sample_path": str(self.sample_path), "output_dir": str(jadx_root)},
                    "Install or expose jadx when the local static tool is unavailable.",
                )
            ] if jadx_result["status"] == "unavailable" else [],
        }

    def _step_native(self) -> dict[str, Any]:
        native_root = self.output_dir / "android" / "native"
        libraries = []
        architectures = set()
        handoffs = []
        with zipfile.ZipFile(self.sample_path) as archive:
            for name in archive.namelist():
                match = re.fullmatch(r"lib/([^/]+)/([^/]+\.so)", name)
                if not match:
                    continue
                architecture, library_name = match.groups()
                architectures.add(architecture)
                payload = archive.read(name)
                destination = native_root / architecture / library_name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                marker_text = payload.decode("latin-1", errors="ignore")
                libraries.append(
                    {
                        "apk_path": name,
                        "path": str(destination),
                        "architecture": architecture,
                        "size": len(payload),
                        "jni": sorted(set(re.findall(r"Java_[A-Za-z0-9_]+|JNI_OnLoad", marker_text))),
                        "signals": [
                            signal
                            for signal in ("AES", "DES", "RSA", "RC4", "DexClassLoader", "socket", "SSL")
                            if signal.lower() in marker_text.lower()
                        ],
                    }
                )
                handoffs.append(
                    self._external_handoff(
                        "reverse_lab_tools",
                        "ghidra_headless_analyze",
                        {"path": str(destination), "project_name": f"{self.pipeline_id}-{library_name}"},
                        "Analyze JNI exports, native crypto, DEX loading, and network behavior in the extracted SO.",
                    )
                )
        return {
            "architectures": sorted(architectures),
            "libraries": libraries,
            "handoffs": handoffs,
        }

    def _step_identify(self) -> dict[str, Any]:
        result = super()._step_identify()
        candidates = list(result.get("key_functions", result.get("candidates", [])))
        dex_matches = self.state["results"].get("dex_java", {}).get("matches", {})
        native_libraries = self.state["results"].get("native", {}).get("libraries", [])
        for category, matches in dex_matches.items():
            if matches:
                candidates.append(
                    {
                        "category": f"android_{category}",
                        "function": "java-layer",
                        "confidence": 0.8,
                        "reasons": [
                            item if isinstance(item, str) else item.get("marker", "")
                            for item in matches
                        ],
                    }
                )
        for library in native_libraries:
            if library["jni"] or library["signals"]:
                candidates.append(
                    {
                        "category": "android_native",
                        "function": library["path"],
                        "confidence": 0.75,
                        "reasons": library["jni"] + library["signals"],
                    }
                )
        result["key_functions"] = candidates
        result["candidates"] = candidates
        return result

    def _step_plan(self) -> dict[str, Any]:
        decrypt_plan = self.decrypt_plan()
        result = {
            "decrypt_unpack_plan": decrypt_plan["path"],
            "handoffs": list(decrypt_plan["handoffs"]),
        }
        hook_path = self._write_artifact(
            "android_frida_hooks",
            "plans/android_hooks.js",
            generate_android_frida_hooks(),
        )
        result.setdefault("handoffs", []).append(
            self._external_handoff(
                "reverse_lab_tools",
                "android_frida_run_script",
                {
                    "target": "<package-or-process>",
                    "script_source": generate_android_frida_hooks(),
                    "mode": "spawn",
                    "duration_seconds": 10,
                },
                "Capture OkHttp, Cipher, WebView, and Base64 activity in an authorized Android sandbox.",
                execute=False,
            )
        )
        result["android_frida_hooks"] = str(hook_path)
        result["handoff_ids"] = [
            item["handoff_id"] for item in result["handoffs"]
        ]
        result["execution_order"] = [
            "Start with spawn mode to hook Application initialization and early native loading.",
            "Trigger login, network synchronization, WebView navigation, and crypto operations.",
            "Collect send() messages and normalize key/IV, plaintext/ciphertext, URLs, and bridge calls.",
        ]
        return result

    def _step_capture(self) -> dict[str, Any]:
        hook_path = self.state.get("artifacts", {}).get("android_frida_hooks")
        frontend = self.state["results"].get("android_frontend", {})
        target = frontend.get("package") or "<package-or-process>"
        ensure_server = self._external_handoff(
            "reverse_lab_tools",
            "android_frida_ensure_server",
            {},
            "Deploy and verify the matching Frida Server on the authorized Android device.",
        )
        http_recipe = self._external_handoff(
            "reverse_lab_tools",
            "android_http_observation_recipe",
            {
                "package_name": target,
                "target_process": target,
                "launch": False,
                "observe_seconds": 10,
            },
            "Capture OkHttp, WebView navigation, and JavaScript bridge activity.",
        )
        crypto_recipe = self._external_handoff(
            "reverse_lab_tools",
            "android_crypto_unpack_recipe",
            {
                "package_name": target,
                "target_process": target,
                "launch": False,
                "observe_seconds": 15,
            },
            "Capture Cipher key/IV, digest, dynamic DEX, dlopen, mmap, and JNI registration evidence.",
        )
        custom_hook = self._external_handoff(
            "reverse_lab_tools",
            "android_frida_run_script",
            {
                "target": target,
                "script_source": Path(hook_path).read_text(encoding="utf-8") if hook_path else generate_android_frida_hooks(),
                "mode": "spawn",
                "duration_seconds": 10,
            },
            "Deploy Frida Server, inject the generated hooks, and return structured send() observations.",
        )
        handoffs = [ensure_server, http_recipe, crypto_recipe, custom_hook]
        if self.backend_runner is None or any(
            item.get("status") != "completed" for item in handoffs
        ):
            return {
                "status": "awaiting-external",
                "handoffs": handoffs,
                "captures": {
                    "crypto": [],
                    "network": [],
                    "webview": [],
                    "base64": [],
                    "native": [],
                },
            }
        return {
            "status": "completed",
            "handoffs": handoffs,
            "captures": {
                item["tool"]: item.get("result", {})
                for item in handoffs
            },
        }

    def decrypt_plan(self) -> dict[str, Any]:
        if self._step_record("triage")["status"] != "completed":
            self.run_step("triage")
        frontend = self.state["results"].get("android_frontend", {})
        package_name = frontend.get("package") or "<package-name>"
        content = "\n".join(
            [
                "# Android Decrypt and Unpack Plan",
                "",
                f"- APK: `{self.sample_path}`",
                f"- Package: `{package_name}`",
                "",
                "1. Ensure Frida Server matches the authorized device ABI.",
                "2. Spawn the package and hook Cipher/key/IV before Application.onCreate completes.",
                "3. Capture OkHttp/WebView/Base64 observations and dynamic DEX/native loading.",
                "4. Post-process Frida JSON into crypto records, buffers, and replay scaffolds.",
                "5. Re-run jadx/Ghidra against dumped DEX/SO artifacts.",
                "",
            ]
        )
        path = self._write_artifact(
            "decrypt_unpack_plan",
            "plans/android-decrypt-unpack-plan.md",
            content,
        )
        handoffs = [
            self._external_handoff(
                "reverse_lab_tools",
                "android_crypto_unpack_recipe",
                {
                    "package_name": package_name,
                    "target_process": package_name,
                    "launch": False,
                    "observe_seconds": 15,
                    "output_path": str(self.output_dir / "captures" / "android-crypto.json"),
                },
                "Capture Android crypto and unpacking evidence with the maintained ReverseLabTools templates.",
                execute=False,
            ),
            self._external_handoff(
                "reverse_lab_tools",
                "postprocess_frida_crypto_result",
                {
                    "result_json_path": str(self.output_dir / "captures" / "android-crypto.json"),
                    "output_subdir": self.pipeline_id,
                    "include_replay": True,
                    "extract_buffers": True,
                    "carve": True,
                },
                "Normalize captured key/IV data and generate replay/decrypt scaffolds and carved artifacts.",
                execute=False,
            ),
        ]
        return {
            "path": path,
            "content": content,
            "requires_unpacking": bool(
                self.state["results"].get("triage", {}).get("requires_unpacking")
            ),
            "detected_packers": self.state["results"].get("triage", {}).get("detected_packers", []),
            "handoffs": handoffs,
            "next_actions": [
                "Execute the Android crypto recipe on an authorized device.",
                "Feed post-processed DEX/SO outputs into jadx and Ghidra.",
            ],
        }

    def _step_produce(self) -> dict[str, Any]:
        result = super()._step_produce()
        android_summary = {
            "manifest": self.state["results"].get("android_frontend", {}),
            "dex_java": self.state["results"].get("dex_java", {}),
            "native": self.state["results"].get("native", {}),
            "capture": self.state["results"].get("capture", {}),
        }
        summary_path = self._write_artifact(
            "android_summary",
            "reports/android_summary.json",
            android_summary,
        )
        result["android_summary"] = str(summary_path)
        return result
