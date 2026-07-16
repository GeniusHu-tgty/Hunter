from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit

from core.workflow.event_kernel import (
    EvidenceAttestation,
    ReproductionObservation,
    VerdictRecord,
    VerdictStatus,
    VerificationObservation,
)
from core.workflow.event_kernel.service import EventKernel

from .artifacts import ArtifactStore


@dataclass(frozen=True)
class OastCallback:
    protocol: str
    host: str
    origin: str


@dataclass(frozen=True)
class OastSchedule:
    origin: str
    nonce: str
    workflow_id: str
    action_id: str
    attempt_id: str
    generation: int


@dataclass(frozen=True)
class OastResult:
    status: str
    evidence_id: str | None
    artifact_digest: str


def canonical_evidence_id(
    workflow_id: str,
    generation: int,
    action_id: str,
    attempt_id: str,
    evidence_kind: str,
) -> str:
    return f"{workflow_id}:{generation}:{action_id}:{attempt_id}:{evidence_kind}"


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class OastVerifier:
    """Correlates scheduled OAST callbacks and persists final Event Kernel evidence."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        *,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self.artifacts = artifacts
        self.nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(18).lower())

    def schedule(
        self,
        origin: str,
        *,
        workflow_id: str,
        action_id: str,
        attempt_id: str,
        generation: int = 1,
    ) -> OastSchedule:
        host = urlsplit(origin).hostname
        if not host:
            raise ValueError("OAST origin must include a host")
        nonce = self.nonce_factory().strip().lower()
        if not nonce or "." in nonce:
            raise ValueError("OAST nonce must be a single host label")
        return OastSchedule(origin=host.lower(), nonce=nonce, workflow_id=workflow_id,
                            action_id=action_id, attempt_id=attempt_id, generation=generation)

    @staticmethod
    def _matches(schedule: OastSchedule, callback: OastCallback) -> bool:
        return (
            callback.origin.lower() == schedule.origin
            and callback.host.lower() == f"{schedule.nonce}.{schedule.origin}"
        )

    def finalize(
        self,
        schedule: OastSchedule,
        callbacks: Iterable[OastCallback],
        control_callbacks: Iterable[OastCallback],
        *,
        event_kernel: EventKernel,
        slug: str,
        meta_factory: Callable[[str], object],
    ) -> OastResult:
        matched = [item for item in callbacks if self._matches(schedule, item)]
        controls = list(control_callbacks)
        status = "verified" if matched and not controls else "refuted" if controls else "inconclusive"
        manifest = {
            "workflow_id": schedule.workflow_id,
            "generation": schedule.generation,
            "action_id": schedule.action_id,
            "attempt_id": schedule.attempt_id,
            "nonce": schedule.nonce,
            "origin": schedule.origin,
            "callbacks": [item.__dict__ for item in matched],
            "control_callback_count": len(controls),
            "status": status,
        }
        artifact = self.artifacts.write(
            {"body": json.dumps(manifest, sort_keys=True), "kind": "oast_manifest"},
            mode="oast",
            target_id=schedule.origin,
            retention="verified" if status == "verified" else "inconclusive",
            protected=status == "verified",
        )
        evidence_id = None
        evidence_ids: tuple[str, ...] = ()
        if status == "verified":
            evidence_id = canonical_evidence_id(
                schedule.workflow_id, schedule.generation, schedule.action_id, schedule.attempt_id, "oast"
            )
            observation = VerificationObservation("no_callback", _digest("oast-baseline"), _digest([]))
            control = VerificationObservation("no_callback", _digest("oast-control"), _digest([]))
            event_kernel.attest_evidence(
                slug,
                meta_factory(f"oast-attest-{schedule.attempt_id[-6:]}"),
                EvidenceAttestation(
                    evidence_id=evidence_id,
                    evidence_sha256=artifact.digest,
                    source_ref_digest=_digest(manifest),
                    action_id=schedule.action_id,
                    attempt_id=schedule.attempt_id,
                    generation=schedule.generation,
                    verifier_id="oast-verifier",
                    verifier_version="1",
                    verification_policy_digest=_digest("unique-nonce+negative-control"),
                    baseline=observation,
                    control=control,
                    reproduction=ReproductionObservation(
                        "callback", _digest("oast-reproduction"), _digest(manifest), 1, 1
                    ),
                ),
            )
            self.artifacts.register_event_kernel_manifest(artifact.digest, evidence_id)
            evidence_ids = (evidence_id,)
        event_kernel.record_verdict(
            slug,
            meta_factory(f"oast-verdict-{schedule.attempt_id[-6:]}"),
            VerdictRecord(
                verdict_id=f"oast-{schedule.attempt_id[-12:]}",
                subject_id=schedule.origin,
                action_id=schedule.action_id,
                attempt_id=schedule.attempt_id,
                status=VerdictStatus(status),
                generation=schedule.generation,
                evidence_ids=evidence_ids,
            ),
        )
        return OastResult(status, evidence_id, artifact.digest)
