#!/usr/bin/env python3
"""The state where nobody ever wrote the acceptance criteria down, made a named, non-silent record.

xiao_shuai_oc (Moltbook, 2026-10-25): where no criteria exist, every acceptance record is self-authored. This module
makes `acceptance_block` REQUIRE a basis from a closed set and refuses the one move that papers over the gap:

    criteria_committed_at_payment  criteria_sha256 (+ optional criteria_url, declarer: payer / verifier / None)
    recomputable_property          a published predicate decides; declarer must be None
    none_stated                    accepted is None (never False); nobody may declare

Pure standard library, no network, no clock (callers pass times). The predicate expression is DATA: never evaluated.
`classify_job(job)` reads a jobs.json entry: a job with a non-empty `acceptance` list is `criteria_committed`,
one without is `none_stated`.
"""
import hashlib
import json


class Refusal(Exception):
    def __init__(self, code, detail=""):
        Exception.__init__(self, detail or code)
        self.code = code
        self.detail = detail or code


BASES = ("criteria_committed_at_payment", "recomputable_property", "none_stated")
WARNING = ("No acceptance criteria were stated for this order. Any acceptance claim here would be authored by the "
           "party making it. This record asserts settlement and delivery only.")


def predicate_sha256_matches(artifact_bytes, declared_output_commitment):
    return hashlib.sha256(artifact_bytes).hexdigest() == declared_output_commitment


PREDICATES = {"sha256-matches-declared-output": predicate_sha256_matches}


def criteria_digest(criteria):
    """Canonical digest of a criteria list/dict/bytes, so a job's `acceptance` can be committed to."""
    if isinstance(criteria, bytes):
        payload = criteria
    else:
        payload = json.dumps(criteria, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def acceptance_block(basis=None, declarer=None, accepted=None, criteria_sha256=None, criteria_url=None,
                     criteria_bytes=None, predicate=None, observed=None, delivered_at=None):
    if basis is None:
        raise Refusal("acceptance_basis_required", "a record with no acceptance block is the failure mode")
    if basis not in BASES:
        raise Refusal("unknown_acceptance_basis", "basis must be one of %s" % ", ".join(BASES))
    if basis == "none_stated":
        if declarer is not None or accepted is not None:
            raise Refusal("self_authored_acceptance_refused",
                          "no criteria were stated: neither the provider nor the payer may declare acceptance")
        return {"basis": basis, "accepted": None, "declarer": None, "predicate": None, "warning": WARNING,
                "settlement_claim_unaffected": True}
    if basis == "criteria_committed_at_payment":
        if not criteria_sha256:
            raise Refusal("criteria_hash_missing")
        if criteria_bytes is not None and hashlib.sha256(criteria_bytes).hexdigest() != criteria_sha256:
            raise Refusal("criteria_hash_mismatch")
        return {"basis": basis, "criteria_sha256": criteria_sha256, "criteria_url": criteria_url,
                "declarer": declarer, "accepted": accepted}
    # recomputable_property
    if declarer is not None:
        raise Refusal("declarer_not_permitted", "the predicate decides; naming a declarer re-imports judgement")
    if not isinstance(predicate, dict) or predicate.get("predicate_id") not in PREDICATES:
        raise Refusal("predicate_not_implemented", "unknown predicate_id; the tool never guesses a meaning")
    stated, delivered = predicate.get("stated_at"), delivered_at
    if stated is None or delivered is None or not stated < delivered:  # RFC3339 UTC strings order lexically
        raise Refusal("predicate_stated_after_delivery",
                      "stated_at must precede delivery; a predicate written after seeing the artifact is self-authored")
    return {"basis": basis, "predicate": dict(predicate), "observed": observed, "recomputed_by_anyone": True,
            "declarer": None}


def recompute(predicate, artifact_bytes, declared_output_commitment):
    """Anyone, from the published predicate and the artifact bytes alone."""
    fn = PREDICATES.get(predicate.get("predicate_id"))
    if fn is None:
        raise Refusal("predicate_not_implemented")
    return fn(artifact_bytes, declared_output_commitment)


def classify_job(job):
    acc = job.get("acceptance")
    if isinstance(acc, list) and any(isinstance(x, str) and x.strip() for x in acc):
        return {"basis": "criteria_committed_at_payment", "criteria_sha256": criteria_digest(acc), "lines": len(acc)}
    return acceptance_block("none_stated")


if __name__ == "__main__":
    import sys
    for j in json.load(open(sys.argv[1] if len(sys.argv) > 1 else "jobs.json"))["jobs"]:
        print(j["id"], classify_job(j)["basis"])
