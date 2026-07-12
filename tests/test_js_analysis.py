from pathlib import Path

import pytest

from core.js_analysis.bundle_unpacker import detect_bundler, unpack_bundle
from core.js_analysis.deobfuscator import deobfuscate


WEBPACK_BUNDLE = r'''
var __webpack_modules__ = ({
  10: function(module, exports, __webpack_require__) {
    const helper = __webpack_require__(20);
    module.exports = helper("/api/users");
  },
  20: function(module) {
    module.exports = function(value) { return value; };
  }
});
function __webpack_require__(moduleId) {
  var module = { exports: {} };
  __webpack_modules__[moduleId](module, module.exports, __webpack_require__);
  return module.exports;
}
__webpack_require__(10);
'''


def test_detects_webpack_bundle():
    result = detect_bundler(WEBPACK_BUNDLE)
    assert result["bundler"] == "webpack"
    assert result["confidence"] >= 0.8
    assert "__webpack_require__" in result["signals"]


def test_unpacks_webpack_modules_and_dependency_tree(tmp_path):
    result = unpack_bundle(WEBPACK_BUNDLE, tmp_path, source_name="app.bundle.js")

    assert result["bundler"] == "webpack"
    assert [module["id"] for module in result["modules"]] == ["10", "20"]
    entry = result["modules"][0]
    assert entry["dependencies"] == ["20"]
    assert entry["exports"] == ["default"]
    assert entry["size"] > 0
    assert (tmp_path / "modules" / "10.js").read_text(encoding="utf-8").startswith("function")
    assert (tmp_path / "module_tree.json").is_file()


def test_replaces_string_array_and_decoder_calls():
    source = r'''
var _0xabc = ['hello', 'world'];
function _0xdec(index) { return _0xabc[index - 0x0]; }
console.log(_0xdec(0x0) + ' ' + _0xdec(0x1));
'''
    result = deobfuscate(source)
    assert 'console.log("hello" + \' \' + "world")' in result["code"]
    assert result["transformations"]["strings_replaced"] == 2


def test_removes_statically_false_branches():
    source = "if (false) { steal(); } else { keep(); } if (!![]) { live(); }"
    result = deobfuscate(source)
    assert "steal" not in result["code"]
    assert "keep();" in result["code"]
    assert "live();" in result["code"]
    assert result["transformations"]["dead_branches_removed"] == 2


def test_recovers_simple_switch_dispatch_sequence():
    source = r'''
var state = 0;
while (true) {
  switch (state) {
    case 0: first(); state = 2; continue;
    case 1: third(); break;
    case 2: second(); state = 1; continue;
  }
  break;
}
'''
    result = deobfuscate(source)
    assert result["basic_blocks"] == ["first();", "second();", "third();"]
    assert "while (true)" not in result["code"]
    assert result["transformations"]["control_flows_recovered"] == 1


def test_expands_argument_free_iife():
    source = "(function(){ const token = 'abc'; use(token); })();"
    result = deobfuscate(source)
    assert "function" not in result["code"]
    assert "const token = 'abc';" in result["code"]
    assert "use(token);" in result["code"]
    assert result["transformations"]["iifes_expanded"] == 1


def test_api_extractor_contract_for_fetch_and_axios():
    from core.js_analysis.api_extractor import extract_api

    result = extract_api("fetch('/api/users', {method: 'POST'}); axios.get('/api/items');")
    assert {(item["method"], item["url"]) for item in result["endpoints"]} == {
        ("POST", "/api/users"),
        ("GET", "/api/items"),
    }


def test_signature_extractor_contract_for_md5():
    from core.js_analysis.signature_extractor import extract_signature

    source = "function sign(p){ return md5(Object.keys(p).sort().join('&') + SALT); }"
    result = extract_signature(source, parameter_name="sign")
    assert result["algorithm"] == "md5"
    assert "sort" in result["operations"]
    assert result["confidence"] > 0
