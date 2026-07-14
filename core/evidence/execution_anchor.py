from __future__ import annotations

import re
from dataclasses import dataclass


class SpeculationLanguageFilter:
    SPECULATION_RE = re.compile(
        r"(?:\u53ef\u80fd|\u4e5f\u8bb8|\u4f3c\u4e4e|\u770b\u8d77\u6765|\u6211\u8ba4\u4e3a|\u7591\u4f3c|probably|might\s+be|may\s+be|likely|seems)",
        re.I,
    )
    TECHNICAL_RE = re.compile(
        r"(?:SQLi|XSS|RCE|SSRF|IDOR|LFI|CSRF|XXE|\u6f0f\u6d1e(?:\u5b58\u5728|\u53d1\u73b0|\u786e\u8ba4)|(?:\u53d1\u73b0|\u786e\u8ba4)\u6f0f\u6d1e)",
        re.I,
    )

    def should_block(self, message: str) -> bool:
        text = str(message or "")
        return bool(self.SPECULATION_RE.search(text) and self.TECHNICAL_RE.search(text))


class UnexecutedClaimBlocker:
    TECHNICAL_RE = SpeculationLanguageFilter.TECHNICAL_RE
    NON_CLAIM_CONTEXT_RE = re.compile(
        r"(?:\u5efa\u8bae|\u68c0\u67e5|\u6d4b\u8bd5|\u9a8c\u8bc1|\u626b\u63cf)(?:[^\n]{0,16})$",
        re.I,
    )
    EXECUTION_RE = re.compile(
        r"(?:\[\s*\d{3}\s*/\s*[^\]]+\]|HTTP/\d(?:\.\d)?\s+\d{3}|\b(?:curl|wget|httpx)\b|\brequests\.(?:get|post|put|patch|delete|request)\s*\(|STATUS:\s*\d{3}|PAYLOAD:\s*\S+)",
        re.I,
    )

    def should_block(self, message: str) -> bool:
        text = str(message or "")
        technical_match = self.TECHNICAL_RE.search(text)
        if not technical_match or self.EXECUTION_RE.search(text):
            return False
        prefix = text[:technical_match.start()].rstrip()
        return not self.NON_CLAIM_CONTEXT_RE.search(prefix)


@dataclass
class ExecutionAnchorEngine:
    speculation_filter: SpeculationLanguageFilter | None = None
    unexecuted_claim_blocker: UnexecutedClaimBlocker | None = None
    blocked_count: int = 0

    def __post_init__(self) -> None:
        self.speculation_filter = self.speculation_filter or SpeculationLanguageFilter()
        self.unexecuted_claim_blocker = self.unexecuted_claim_blocker or UnexecutedClaimBlocker()

    def process(self, message: str) -> dict[str, object]:
        if self.speculation_filter.should_block(message):
            blocker = "speculation_language"
        elif self.unexecuted_claim_blocker.should_block(message):
            blocker = "unexecuted_claim"
        else:
            blocker = None
        if blocker:
            self.blocked_count += 1
        return {
            "blocked": blocker is not None,
            "blocker": blocker,
            "inject_message": self._inject_message(blocker),
            "blocked_count": self.blocked_count,
        }

    @staticmethod
    def _inject_message(blocker: str | None) -> str:
        if blocker == "speculation_language":
            return "\u8bf7\u5c06\u63a8\u6d4b\u6027\u6280\u672f\u58f0\u660e\u66ff\u6362\u4e3a\u5df2\u6267\u884c\u3001\u53ef\u590d\u73b0\u7684\u8bc1\u636e\u3002"
        if blocker == "unexecuted_claim":
            return "\u8bf7\u5148\u6267\u884c\u9a8c\u8bc1\u5e76\u9644\u4e0a HTTP \u72b6\u6001\u3001\u5de5\u5177\u8c03\u7528\u6216\u54cd\u5e94\u8bc1\u636e\u3002"
        return ""