"""
Hunter v7 Core Module

鏍稿績妯″潡锛屽寘鍚細
- Result 绫诲瀷
- 婕忔礊鍒嗙被绯荤粺
- 婕忔礊鍙戠幇鏁版嵁缁撴瀯
- PoC 楠岃瘉鍣?
- 鎶ュ憡杩囨护鍣?
- PoC 宸ヤ綔娴?
- 闃舵瀹氫箟
- Agent 瀹氫箟
- 骞惰鎵ц寮曟搸
- Git 妫€鏌ョ偣绠＄悊
- 瀹¤鏃ュ織
- 婕忔礊閾惧紩鎿?
"""

from .result import Result, ok, err
from .vuln_classification import VulnClassification
from .vuln_finding import VulnFinding, SubmissionTier, ProofStrength
from .poc_verifier import PoCVerifier
from .report_filter import ReportFilter
from .poc_workflow import PoCWorkflow
from .phases import PHASES, PhaseName, PhaseConfig
from .agents import AGENTS, AgentDefinition, ModelTier
from .parallel_executor import ParallelExecutor, AgentTask
from .git_manager import GitManager
from .audit import AuditSession, AuditEntry
from .chains import VULN_CHAINS, VulnChain, VulnChainStep
from .burp_adapter import classify_burp_exports, suggest_hunter_prefix
from .burp_import import import_burp_evidence
from .draft_generator import generate_submission_draft_from_burp

__all__ = [
    # Result
    'Result', 'ok', 'err',

    # Classification
    'VulnClassification',

    # Finding
    'VulnFinding', 'SubmissionTier', 'ProofStrength',

    # PoC
    'PoCVerifier', 'ReportFilter', 'PoCWorkflow',

    # Phases
    'PHASES', 'PhaseName', 'PhaseConfig',

    # Agents
    'AGENTS', 'AgentDefinition', 'ModelTier',

    # Execution
    'ParallelExecutor', 'AgentTask',

    # Git
    'GitManager',

    # Audit
    'AuditSession', 'AuditEntry',

    # Chains
    'VULN_CHAINS', 'VulnChain', 'VulnChainStep',
    'classify_burp_exports', 'suggest_hunter_prefix',
    'import_burp_evidence',
    'generate_submission_draft_from_burp',
]

