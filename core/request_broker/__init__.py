"""Single HTTP policy and evidence boundary for Hunter request execution."""

from .broker import (
    BrokerOutcome,
    BrokerSettings,
    BrokerTransport,
    Classification,
    LegacyRequestsAdapter,
    RequestBroker,
    RequestSpec,
    load_broker_settings,
)
from .mitm_controller import DependentProcess, MitmController, MitmStatus
from .artifacts import ArtifactStore, ArtifactWrite
from .identity import Identity, IdentityPool
from .attack_list import build_attack_list
from .transport import AsyncHttpxRaceTransport
from .oast import OastCallback, OastResult, OastSchedule, OastVerifier, canonical_evidence_id
from .projection import ResponseProjection, block_cluster_similarity, build_response_projection

__all__ = [
    "BrokerOutcome",
    "BrokerSettings",
    "BrokerTransport",
    "Classification",
    "LegacyRequestsAdapter",
    "RequestBroker",
    "RequestSpec",
    "load_broker_settings",
    "DependentProcess",
    "MitmController",
    "MitmStatus",
    "ArtifactStore",
    "ArtifactWrite",
    "Identity",
    "IdentityPool",
    "build_attack_list",
    "AsyncHttpxRaceTransport",
    "OastCallback",
    "OastResult",
    "OastSchedule",
    "OastVerifier",
    "canonical_evidence_id",
    "ResponseProjection",
    "block_cluster_similarity",
    "build_response_projection",
]
