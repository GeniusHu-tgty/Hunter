"""
Hunter v8 agent registry tests.

The current architecture uses declarative AgentDefinition entries in core.agents
and phase routing in core.phases. Older package-style agents/* modules are no
longer part of this repo, so these tests validate the live registry instead.
"""

from core.agents import AGENTS, AgentDefinition, ModelTier
from core.phases import PHASES, PhaseName


def test_agent_registry_has_expected_size_and_core_agents():
    assert len(AGENTS) == 39
    for name in [
        "subdomain", "port-scan", "tech-detect", "js-analyze",
        "sqli-vuln", "xss-vuln", "ssrf-vuln", "jwt-vuln", "idor-vuln",
        "sqli-exploit", "idor-exploit", "chain-exploit",
        "evidence-collect", "report-generate",
    ]:
        assert name in AGENTS
        assert isinstance(AGENTS[name], AgentDefinition)


def test_agent_definitions_are_complete():
    for name, agent in AGENTS.items():
        assert agent.name == name
        assert agent.display_name
        assert agent.description
        assert agent.prompt_template
        assert agent.deliverable_filename
        assert isinstance(agent.model_tier, ModelTier)
        assert agent.timeout > 0
        assert agent.max_retries >= 0
        assert isinstance(agent.tools_required, list)
        assert isinstance(agent.payload_types, list)


def test_phase_configs_reference_existing_agents():
    assert set(PHASES) == {
        PhaseName.PRE_RECON,
        PhaseName.RECON,
        PhaseName.VULN_ANALYSIS,
        PhaseName.EXPLOITATION,
        PhaseName.REPORTING,
    }
    phase_agents = []
    for phase, config in PHASES.items():
        assert config.name == phase
        assert config.display_name
        assert config.agents
        assert all(agent_name in AGENTS for agent_name in config.agents)
        phase_agents.extend(config.agents)
    assert set(phase_agents) == set(AGENTS)


def test_phase_agent_counts_match_design():
    assert len(PHASES[PhaseName.PRE_RECON].agents) == 5
    assert len(PHASES[PhaseName.RECON].agents) == 5
    assert len(PHASES[PhaseName.VULN_ANALYSIS].agents) == 13
    assert len(PHASES[PhaseName.EXPLOITATION].agents) == 12
    assert len(PHASES[PhaseName.REPORTING].agents) == 4


def test_payload_backed_agents_use_known_payload_types():
    known_payload_types = {"deser", "info_leak", "jwt", "lfi", "sqli", "ssti", "xss", "xxe"}
    payload_backed = [agent for agent in AGENTS.values() if agent.payload_types]
    assert payload_backed
    for agent in payload_backed:
        # Some planned agents such as upload/rce/ssrf intentionally use scanner logic
        # without bundled YAML yet; they remain allowed as lead-only scan agents.
        assert set(agent.payload_types).issubset(known_payload_types | {"upload", "rce", "ssrf"})
