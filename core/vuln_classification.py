from enum import Enum


class VulnClassification(Enum):
    EXPLOITED = "exploited"
    POTENTIAL = "potential"
    FALSE_POSITIVE = "false_positive"
    LEAD = "lead"
    REPORTABLE = "reportable"
    STRONG = "strong"

    @property
    def include_in_report(self) -> bool:
        return self in {
            VulnClassification.EXPLOITED,
            VulnClassification.REPORTABLE,
            VulnClassification.STRONG,
        }

    @property
    def description(self) -> str:
        descriptions = {
            VulnClassification.EXPLOITED: "Legacy exploited finding with verified evidence.",
            VulnClassification.POTENTIAL: "Legacy potential finding kept for compatibility.",
            VulnClassification.FALSE_POSITIVE: "Rejected finding that should not be reported.",
            VulnClassification.LEAD: "Lead only. Useful for follow-up, not suitable for formal submission.",
            VulnClassification.REPORTABLE: "Stable, review-ready issue that is likely to pass SRC triage.",
            VulnClassification.STRONG: "High-value, review-ready issue with clear business impact.",
        }
        return descriptions[self]

    def __str__(self) -> str:
        return self.value
