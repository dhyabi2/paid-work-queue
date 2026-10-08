"""The binding `ockerclaw` asked for four times, and the rule it rests on.

The decisive tests here are 1, 4 and 12.

Test 1 is `ockerclaw`'s own test, in their words: crash after send confirmation
but before recording it locally, then restart with the same idempotency key.
The journal object is discarded entirely and reloaded from disk, which is the
only way to drive the case they named; a test that reuses the in-memory journal
proves nothing about a restart.

Test 4 is the property, not a case. For every one of the nine states,
`safe_action(...)["blocks_new_send"]` is True unless the state is
`ABANDONED_NO_SEND`, and the states are enumerated from the module, so a tenth
state fails this test by default rather than slipping in with a permissive
default.

Test 12 is the one a "repair the journal" implementation fails. A file
truncated mid-write is refused, and NOT replaced with a fresh empty journal:
starting clean over a half-written journal is how the second payment happens.

Test 13 asserts the fsync, because an atomic rename over data still in the page
cache survives a process crash and not a machine one, and `ockerclaw`'s test is
about a crash.

Every fixture is built here rather than taken from the module's own `--self-test`
controls, deliberately: driving these assertions from the module's fixtures
would let one mutation break both and drift past green.

Nothing opens a socket, and nothing can: test 16 walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import canonical  # noqa: E402
import nanoaddr  # noqa: E402
import retry_safety  # noqa: E402
import validate  # noqa: E402
from retry_safety import (  # noqa: E402
    ABANDONED_NO_SEND, COMPLETE, DEFAULT_RECONCILE_BUDGET,
    EVIDENCE_UNAVAILABLE, IMMUTABLE_FIELDS, INCONCLUSIVE_KINDS, REQUESTED,
    SAFE_ACTIONS, SENT_CONFIRMED_UNRECEIVED, SENT_UNCONFIRMED, SETTLED,
    SETTLED_RESULT_PENDING, SIGNED_NOT_BROADCAST, STATES, TERMINAL, Refusal,
    binding_for_payment, idempotency_key_for, empty_journal, expire, import_graph,
    observe, open_attempt, read_journal, rebroadcast_block, reconcile_report,
    record_broadcast, record_result, record_signed, safe_action, state_table,
    write_journal,
)

SCRIPT = os.path.join(ROOT, "retry_safety.py")

NOW = "2026-10-08T07:00:00Z"
LATER = "2026-10-08T09:00:00Z"
MUCH_LATER = "2026-10-12T07:00:00Z"
A_YEAR_ON = "2027-10-08T07:00:00Z"

AMOUNT = "50000000000000000000000000000"
ORDER_DIGEST = "a1b2" * 16
ORDER_DIGEST_HALVES = [ORDER_DIGEST[:32], ORDER_DIGEST[32:]]


def address():
    """A payable address built from a public key, not pasted from anywhere."""
    return nanoaddr.encode(bytes(range(32)), "nano_")


def other_address():
    return nanoaddr.encode(bytes(range(1, 33)), "nano_")


def block_hash(seed="A"):
    return seed * 64


def signed_block(payee, link=None, signature=None):
    """A send block shaped the way a node returns one. No key material."""
    return {
        "type": "state",
        "account": payee,
        "previous": "b" * 64,
        "representative": payee,
        "balance": "0",
        "link": link or "c" * 64,
        "link_as_account": payee,
        "signature": signature or "d" * 128,
        "work": "0000000000000000",
        "subtype": "send",
    }


def opened(now=NOW, **kwargs):
    fields = {"order_digest": ORDER_DIGEST, "amount_raw": AMOUNT,
              "payee": address()}
    fields.update(kwargs)
    return open_attempt(empty_journal(), now=now, **fields)


def through_broadcast(now=NOW):
    journal, attempt = opened(now)
    key = attempt["idempotency_key"]
    journal, _ = record_signed(journal, key, signed_block(address()),
                               block_hash(), now=now)
    journal, attempt = record_broadcast(journal, key, now=now)
    return journal, key, attempt


class OckerclawsRestartTest(unittest.TestCase):
    """Test 1 and test 2: the two crash windows they named."""

    def test_01_crash_after_confirmation_before_recording_it_locally(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            journal, key, _ = through_broadcast()
            journal, _ = observe(journal, key,
                                 {"kind": "confirmed", "at": NOW,
                                  "node": "https://node.invalid"}, now=NOW)
            write_journal(path, journal)

            # The crash. Nothing in memory survives it.
            del journal

            reloaded = read_journal(path)
            with self.assertRaises(Refusal) as caught:
                open_attempt(reloaded, order_digest=ORDER_DIGEST,
                             amount_raw=AMOUNT, payee=address(), now=LATER)
            self.assertEqual(caught.exception.code, "duplicate_open")
            recovered = caught.exception.attempt
            self.assertIsNotNone(
                recovered, "a crashed caller must get the row back, not just a "
                           "refusal code")
            self.assertEqual(recovered["idempotency_key"], key)
            verdict = safe_action(recovered, now=LATER)
            self.assertIn(verdict["action"],
                          ("REBROADCAST_SAME_BLOCK",
                           "WAIT_OR_REBROADCAST_SAME_BLOCK", "FETCH_RESULT",
                           "HOLD_FOR_OPERATOR", "NOTHING"))
            self.assertTrue(verdict["blocks_new_send"])
            self.assertEqual(verdict["rebroadcast_block"],
                             signed_block(address()))

    def test_02_crash_between_signing_and_broadcasting(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            journal, attempt = opened()
            key = attempt["idempotency_key"]
            block = signed_block(address())
            journal, _ = record_signed(journal, key, block, block_hash(),
                                       now=NOW)
            write_journal(path, journal)
            del journal

            reloaded = read_journal(path)
            row = retry_safety.require(reloaded, key)
            self.assertEqual(row["state"], SIGNED_NOT_BROADCAST)
            verdict = safe_action(row, now=LATER)
            self.assertEqual(verdict["action"], "BROADCAST_SAME_BLOCK")
            self.assertTrue(verdict["blocks_new_send"])
            self.assertEqual(verdict["rebroadcast_block"], block)


class NotFoundIsNotAFactTest(unittest.TestCase):
    """Test 3: the rule the whole module exists for."""

    def test_03_inconclusive_observations_never_authorise_a_fresh_send(self):
        for kind in INCONCLUSIVE_KINDS:
            with self.subTest(kind=kind):
                journal, key, _ = through_broadcast()
                attempt = None
                for _ in range(DEFAULT_RECONCILE_BUDGET * 2):
                    journal, attempt = observe(
                        journal, key,
                        {"kind": kind, "at": NOW, "node": "https://n.invalid"},
                        now=NOW)
                    self.assertNotEqual(attempt["state"], ABANDONED_NO_SEND)
                    self.assertTrue(
                        safe_action(attempt, now=NOW)["blocks_new_send"],
                        "%s authorised a new send" % kind)
                self.assertEqual(attempt["state"], EVIDENCE_UNAVAILABLE)
                self.assertEqual(safe_action(attempt, now=NOW)["action"],
                                 "HOLD_FOR_OPERATOR")

    def test_03b_the_budget_is_spent_exactly_once_and_recorded(self):
        journal, key, _ = through_broadcast()
        attempt = None
        for index in range(DEFAULT_RECONCILE_BUDGET):
            journal, attempt = observe(journal, key, {"kind": "not_found",
                                                      "at": NOW, "node": None},
                                       now=NOW)
            self.assertEqual(attempt["reconcile_attempts"], index + 1)
        self.assertEqual(attempt["budget_expired_at"], NOW)
        expired = [e for e in attempt["history"]
                   if e["event"] == "budget_expired"]
        self.assertEqual(len(expired), 1)
        journal, attempt = observe(journal, key, {"kind": "not_found",
                                                  "at": NOW, "node": None},
                                   now=LATER)
        self.assertEqual(attempt["budget_expired_at"], NOW,
                         "the moment the budget ran out does not move")


class TheOneStatePropertyTest(unittest.TestCase):
    """Test 4 and test 14: enumerated over the module, not written out here."""

    def test_04_a_new_send_is_blocked_in_every_state_but_one(self):
        permitted = []
        for state in STATES:
            verdict = safe_action({"state": state, "signed_block": None},
                                  now=NOW)
            if not verdict["blocks_new_send"]:
                permitted.append(state)
            self.assertEqual(verdict["action"], SAFE_ACTIONS[state])
            self.assertTrue(verdict["why"].strip())
        self.assertEqual(permitted, [ABANDONED_NO_SEND])

    def test_14_every_state_has_an_action_and_no_action_lacks_a_state(self):
        self.assertEqual(set(STATES), set(SAFE_ACTIONS))
        self.assertEqual(len(STATES), 9)
        self.assertEqual(
            {row["state"] for row in state_table()}, set(STATES),
            "the published table and the code must name the same states")
        for row in state_table():
            self.assertEqual(row["blocks_new_send"],
                             row["state"] != ABANDONED_NO_SEND)

    def test_04b_safe_to_retry_fresh_is_reachable_from_one_state_only(self):
        reachable = [s for s in STATES
                     if SAFE_ACTIONS[s] == "SAFE_TO_RETRY_FRESH"]
        self.assertEqual(reachable, [ABANDONED_NO_SEND])


class AbandonmentTest(unittest.TestCase):
    """Test 5: the one door to a fresh send, and that a block closes it."""

    def test_05_a_signed_row_is_never_abandoned_however_old(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        journal, _ = record_signed(journal, key, signed_block(address()),
                                   block_hash(), now=NOW)
        after, changed = expire(journal, now=A_YEAR_ON, request_ttl_hours=1)
        row = retry_safety.require(after, key)
        self.assertEqual(row["state"], SIGNED_NOT_BROADCAST)
        self.assertEqual([c for c in changed if c["what"] == "abandoned"], [])
        self.assertTrue(safe_action(row, now=A_YEAR_ON)["blocks_new_send"])

    def test_05b_an_unsigned_expired_request_is_abandoned(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        after, changed = expire(journal, now=MUCH_LATER, request_ttl_hours=24)
        row = retry_safety.require(after, key)
        self.assertEqual(row["state"], ABANDONED_NO_SEND)
        self.assertIn({"key": key, "what": "abandoned"}, changed)
        verdict = safe_action(row, now=MUCH_LATER)
        self.assertEqual(verdict["action"], "SAFE_TO_RETRY_FRESH")
        self.assertFalse(verdict["blocks_new_send"])
        self.assertIsNone(verdict["rebroadcast_block"])

    def test_05c_an_unexpired_request_is_left_alone(self):
        journal, attempt = opened()
        after, changed = expire(journal, now=LATER, request_ttl_hours=24)
        self.assertEqual(changed, [])
        self.assertEqual(
            retry_safety.require(after, attempt["idempotency_key"])["state"],
            REQUESTED)


class SecondSignatureTest(unittest.TestCase):
    """Test 6: one request, one signature."""

    def test_06_a_different_block_refuses_and_changes_nothing(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        journal, _ = record_signed(journal, key, signed_block(address()),
                                   block_hash(), now=NOW)
        before = json.dumps(journal, sort_keys=True)
        with self.assertRaises(Refusal) as caught:
            record_signed(journal, key, signed_block(address(),
                                                     link="e" * 64),
                          block_hash("F"), now=LATER)
        self.assertEqual(caught.exception.code, "already_signed")
        self.assertEqual(json.dumps(journal, sort_keys=True), before)

    def test_06b_the_same_block_is_idempotent(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        block = signed_block(address())
        once, first = record_signed(journal, key, block, block_hash(), now=NOW)
        twice, second = record_signed(once, key, block, block_hash(), now=LATER)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(once, sort_keys=True),
                         json.dumps(twice, sort_keys=True))

    def test_06c_the_same_block_under_a_different_hash_refuses(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        block = signed_block(address())
        journal, _ = record_signed(journal, key, block, block_hash(), now=NOW)
        with self.assertRaises(Refusal) as caught:
            record_signed(journal, key, block, block_hash("E"), now=LATER)
        self.assertEqual(caught.exception.code, "already_signed")


class DerivedKeyTest(unittest.TestCase):
    """Test 7: computed here with stdlib, with no import of the helper."""

    def test_07_the_key_is_derived_from_the_request_alone(self):
        payee = address()
        material = (bytes.fromhex(ORDER_DIGEST) + AMOUNT.encode("ascii")
                    + payee.encode("ascii"))
        expected = "ik-" + hashlib.blake2b(material,
                                           digest_size=16).hexdigest()
        _journal, attempt = opened()
        self.assertEqual(attempt["idempotency_key"], expected)

    def test_07b_two_fresh_processes_agree_on_the_key(self):
        payee = address()
        runs = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as home:
                result = subprocess.run(
                    [sys.executable, SCRIPT, "open",
                     "--order-digest", ORDER_DIGEST, "--amount-raw", AMOUNT,
                     "--payee", payee, "--now", NOW,
                     "--journal", os.path.join(home, "attempts.json")],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                runs.append(json.loads(result.stdout)["idempotency_key"])
        self.assertEqual(runs[0], runs[1])

    def test_07c_a_different_request_is_a_different_key(self):
        _j, one = opened()
        _k, two = opened(payee=other_address())
        _l, three = opened(amount_raw=str(int(AMOUNT) + 1))
        keys = {one["idempotency_key"], two["idempotency_key"],
                three["idempotency_key"]}
        self.assertEqual(len(keys), 3)


class ConfirmedButUnreceivedTest(unittest.TestCase):
    """Test 8: the literal case in `ockerclaw`'s first message."""

    def test_08_budget_spent_on_a_confirmed_unreceived_send(self):
        journal, key, _ = through_broadcast()
        journal, attempt = observe(journal, key, {"kind": "confirmed",
                                                  "at": NOW, "node": None},
                                   now=NOW)
        self.assertEqual(attempt["state"], SENT_CONFIRMED_UNRECEIVED)
        self.assertEqual(safe_action(attempt, now=NOW)["action"],
                         "WAIT_OR_REBROADCAST_SAME_BLOCK")
        for _ in range(DEFAULT_RECONCILE_BUDGET):
            journal, attempt = observe(journal, key, {"kind": "not_found",
                                                      "at": NOW, "node": None},
                                       now=LATER)
        self.assertEqual(attempt["state"], EVIDENCE_UNAVAILABLE)
        self.assertEqual(safe_action(attempt, now=LATER)["action"],
                         "HOLD_FOR_OPERATOR")
        report = reconcile_report(journal, now=LATER)
        self.assertIn(key, report["needs_operator"])
        self.assertEqual(report["evidence_unavailable"], 1)
        self.assertEqual(report["in_flight"], 1)
        self.assertAlmostEqual(report["oldest_unresolved_hours"], 2.0, places=3)

    def test_08b_a_received_observation_settles_it(self):
        journal, key, _ = through_broadcast()
        journal, attempt = observe(journal, key, {"kind": "received",
                                                  "at": NOW, "node": None},
                                   now=NOW)
        self.assertEqual(attempt["state"], SETTLED)
        self.assertEqual(attempt["received_at"], NOW)
        self.assertEqual(attempt["confirmed_at"], NOW,
                         "a confirmed receive proves the send confirmed")
        self.assertTrue(safe_action(attempt, now=NOW)["blocks_new_send"])

    def test_08c_a_confirmation_needs_a_block_to_be_about(self):
        journal, attempt = opened()
        with self.assertRaises(Refusal) as caught:
            observe(journal, attempt["idempotency_key"],
                    {"kind": "confirmed", "at": NOW, "node": None}, now=NOW)
        self.assertEqual(caught.exception.code, "no_block_to_confirm")


class TriStateResultTest(unittest.TestCase):
    """Test 9: an unknown is not a no."""

    def settled(self):
        journal, key, _ = through_broadcast()
        journal, _ = observe(journal, key, {"kind": "received", "at": NOW,
                                            "node": None}, now=NOW)
        return journal, key

    def test_09_unknown_and_no_stay_pending_and_only_yes_completes(self):
        for value, expected in (("UNKNOWN", SETTLED_RESULT_PENDING),
                                ("NO", SETTLED_RESULT_PENDING),
                                ("YES", COMPLETE)):
            with self.subTest(retrievable=value):
                journal, key = self.settled()
                journal, attempt = record_result(
                    journal, key, "https://example.invalid/result.json",
                    retrievable=value, now=LATER)
                self.assertEqual(attempt["state"], expected)
                self.assertEqual(attempt["result_retrievable"], value)

    def test_09b_a_boolean_is_refused(self):
        journal, key = self.settled()
        for value in (True, False, 1, 0, "yes", None):
            with self.subTest(value=value):
                with self.assertRaises(Refusal) as caught:
                    record_result(journal, key, "https://e.invalid/r",
                                  retrievable=value, now=LATER)
                self.assertEqual(caught.exception.code, "bad_retrievable")

    def test_09c_a_result_before_the_money_landed_is_refused(self):
        journal, key, _ = through_broadcast()
        with self.assertRaises(Refusal) as caught:
            record_result(journal, key, "https://e.invalid/r",
                          retrievable="YES", now=LATER)
        self.assertEqual(caught.exception.code, "not_settled")

    def test_09e_a_result_with_no_reference_is_refused(self):
        """`SETTLED_RESULT_PENDING` must not be reachable by naming nothing."""
        journal, key = self.settled()
        for value in ("", "   ", None, 7, [], {}):
            with self.subTest(result_ref=value):
                with self.assertRaises(Refusal) as caught:
                    record_result(journal, key, value, retrievable="YES",
                                  now=LATER)
                self.assertEqual(caught.exception.code, "bad_observation")

    def test_09d_a_pending_result_can_become_retrievable(self):
        journal, key = self.settled()
        journal, _ = record_result(journal, key, "https://e.invalid/r",
                                   retrievable="UNKNOWN", now=LATER)
        journal, attempt = record_result(journal, key, "https://e.invalid/r",
                                         retrievable="YES", now=MUCH_LATER)
        self.assertEqual(attempt["state"], COMPLETE)


class RetentionTest(unittest.TestCase):
    """Test 10: retention must not delete a forgotten in-flight payment."""

    def aged_row(self, state):
        journal, key, _ = through_broadcast()
        if state == EVIDENCE_UNAVAILABLE:
            for _ in range(DEFAULT_RECONCILE_BUDGET):
                journal, _ = observe(journal, key, {"kind": "not_found",
                                                    "at": NOW, "node": None},
                                     now=NOW)
        elif state == COMPLETE:
            journal, _ = observe(journal, key, {"kind": "received", "at": NOW,
                                                "node": None}, now=NOW)
            journal, _ = record_result(journal, key, "https://e.invalid/r",
                                       retrievable="YES", now=NOW)
        journal["retention_hours"] = 1
        return journal, key

    def test_10_a_non_terminal_row_survives_any_age(self):
        journal, key = self.aged_row(EVIDENCE_UNAVAILABLE)
        after, changed = expire(journal, now=A_YEAR_ON)
        self.assertIsNotNone(retry_safety.find(after, key))
        self.assertEqual([c for c in changed if c["what"] == "dropped"], [])

    def test_10b_a_terminal_row_past_retention_is_dropped(self):
        journal, key = self.aged_row(COMPLETE)
        after, changed = expire(journal, now=A_YEAR_ON)
        self.assertIsNone(retry_safety.find(after, key))
        self.assertIn({"key": key, "what": "dropped"}, changed)

    def test_10c_a_terminal_row_inside_retention_is_kept(self):
        journal, key = self.aged_row(COMPLETE)
        journal["retention_hours"] = 720
        after, changed = expire(journal, now=LATER)
        self.assertIsNotNone(retry_safety.find(after, key))
        self.assertEqual(changed, [])

    def test_10d_every_state_outside_terminal_is_kept(self):
        for state in STATES:
            if state in TERMINAL:
                continue
            with self.subTest(state=state):
                # A state meaning "no block exists" needs an unsigned row: the
                # loader refuses the contradiction, which is test 12f.
                if state in retry_safety.NO_BLOCK_STATES:
                    journal, attempt = opened()
                    key = attempt["idempotency_key"]
                else:
                    journal, key, _ = through_broadcast()
                retry_safety.find(journal, key)["state"] = state
                journal["retention_hours"] = 1
                after, _ = expire(journal, now=A_YEAR_ON,
                                  request_ttl_hours=10 ** 6)
                self.assertIsNotNone(retry_safety.find(after, key),
                                     "%s was dropped by retention" % state)


class PurityTest(unittest.TestCase):
    """Test 11: the function a caller consults before touching money."""

    def test_11_safe_action_writes_nothing(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            journal, key, _ = through_broadcast()
            write_journal(path, journal)
            with open(path, "rb") as handle:
                before = handle.read()
            stat_before = os.stat(path)
            attempt = retry_safety.require(read_journal(path), key)
            snapshot = json.dumps(attempt, sort_keys=True)
            for _ in range(100):
                safe_action(attempt, now=NOW)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before)
            self.assertEqual(os.stat(path).st_mtime_ns, stat_before.st_mtime_ns)
            self.assertEqual(json.dumps(attempt, sort_keys=True), snapshot,
                             "safe_action mutated the row it was given")
            self.assertEqual(sorted(os.listdir(home)), ["attempts.json"])


class CorruptJournalTest(unittest.TestCase):
    """Test 12: never repaired, never replaced."""

    def test_12_a_truncated_journal_is_refused_and_left_alone(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            journal, _key, _ = through_broadcast()
            whole = json.dumps(journal, indent=1)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(whole[:len(whole) // 2])
            with open(path, "rb") as handle:
                before = handle.read()
            with self.assertRaises(Refusal) as caught:
                read_journal(path)
            self.assertEqual(caught.exception.code, "bad_journal")
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before,
                                 "a half-written journal is evidence")
            self.assertEqual(sorted(os.listdir(home)), ["attempts.json"])

    def test_12b_the_cli_refuses_rather_than_starting_clean(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"v": "attempts-v1", "attempts": [')
            result = subprocess.run(
                [sys.executable, SCRIPT, "open", "--order-digest",
                 ORDER_DIGEST, "--amount-raw", AMOUNT, "--payee", address(),
                 "--now", NOW, "--journal", path],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("reason=bad_journal", result.stderr)
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(),
                                 '{"v": "attempts-v1", "attempts": [')

    def test_12c_a_missing_journal_is_a_first_run_not_a_refusal(self):
        with tempfile.TemporaryDirectory() as home:
            journal = read_journal(os.path.join(home, "attempts.json"))
            self.assertEqual(journal["attempts"], [])

    def test_12d_a_row_in_an_unknown_state_is_refused(self):
        journal, _key, _ = through_broadcast()
        journal["attempts"][0]["state"] = "PROBABLY_FINE"
        with self.assertRaises(Refusal) as caught:
            retry_safety.checked_journal(journal)
        self.assertEqual(caught.exception.code, "bad_state")

    def test_12f_a_row_that_says_no_block_exists_and_carries_one_is_refused(self):
        """The contradiction that could authorise a second payment."""
        journal, key, _ = through_broadcast()
        for state in (REQUESTED, ABANDONED_NO_SEND):
            with self.subTest(state=state):
                edited = json.loads(json.dumps(journal))
                retry_safety.find(edited, key)["state"] = state
                with self.assertRaises(Refusal) as caught:
                    retry_safety.checked_journal(edited)
                self.assertEqual(caught.exception.code, "bad_state")
                self.assertIn("signed block", caught.exception.message)

    def test_12g_a_hand_edited_journal_cannot_be_expired_into_a_fresh_send(self):
        """`expire` is the only door to SAFE_TO_RETRY_FRESH; this is the lock."""
        journal, key, _ = through_broadcast()
        edited = json.loads(json.dumps(journal))
        retry_safety.find(edited, key)["state"] = REQUESTED
        with self.assertRaises(Refusal) as caught:
            expire(edited, now=A_YEAR_ON, request_ttl_hours=1)
        self.assertEqual(caught.exception.code, "bad_state")

    def test_12h_a_journal_that_is_not_a_readable_file_is_refused(self):
        """A directory where the journal should be: an OSError, not an empty one."""
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            os.mkdir(path)
            with self.assertRaises(Refusal) as caught:
                read_journal(path)
            self.assertEqual(caught.exception.code, "bad_journal")

    def test_12e_one_key_names_one_row(self):
        journal, _key, _ = through_broadcast()
        journal["attempts"].append(json.loads(json.dumps(
            journal["attempts"][0])))
        with self.assertRaises(Refusal) as caught:
            retry_safety.checked_journal(journal)
        self.assertEqual(caught.exception.code, "bad_journal")


class DurableWriteTest(unittest.TestCase):
    """Test 13 and test 17: the write that must survive a crash."""

    def test_13_the_temp_file_is_fsynced_before_the_replace(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            journal, _key, _ = through_broadcast()
            order = []
            real_fsync, real_replace = os.fsync, os.replace

            def counting_fsync(fd):
                order.append(("fsync", fd))
                return real_fsync(fd)

            def watching_replace(src, dst):
                order.append(("replace", src))
                return real_replace(src, dst)

            os.fsync, os.replace = counting_fsync, watching_replace
            try:
                write_journal(path, journal)
            finally:
                os.fsync, os.replace = real_fsync, real_replace
            kinds = [entry[0] for entry in order]
            self.assertIn("fsync", kinds, "the journal was never flushed")
            self.assertIn("replace", kinds)
            self.assertLess(kinds.index("fsync"), kinds.index("replace"),
                            "the rename happened before the flush")
            self.assertTrue(order[kinds.index("replace")][1].endswith(".tmp"))

    def test_17_a_failed_write_leaves_no_tmp_and_the_old_journal_intact(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            journal, _key, _ = through_broadcast()
            write_journal(path, journal)
            with open(path, "rb") as handle:
                before = handle.read()
            real_replace = os.replace

            def failing_replace(src, dst):
                raise OSError("the disk went away")

            os.replace = failing_replace
            try:
                with self.assertRaises(OSError):
                    write_journal(path, journal)
            finally:
                os.replace = real_replace
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before)
            self.assertEqual(sorted(os.listdir(home)), ["attempts.json"])

    def test_17b_a_refused_document_is_never_written(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            with self.assertRaises(Refusal):
                write_journal(path, {"v": "attempts-v0", "retention_hours": 1,
                                     "attempts": []})
            self.assertEqual(os.listdir(home), [])


class NoKeyMaterialTest(unittest.TestCase):
    """Test 15, and the secret gate over the file this module writes."""

    def test_15_a_block_naming_a_key_or_a_seed_is_refused(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        for field in ("private", "private_key", "seed", "wallet_seed",
                      "SECRET", "mnemonic"):
            with self.subTest(field=field):
                with self.assertRaises(Refusal) as caught:
                    record_signed(journal, key,
                                  dict(signed_block(address()),
                                       **{field: "x"}),
                                  block_hash(), now=NOW)
                self.assertEqual(caught.exception.code, "unknown_field")

    def test_15b_a_signature_is_public_and_is_kept(self):
        journal, attempt = opened()
        key = attempt["idempotency_key"]
        block = signed_block(address())
        journal, attempt = record_signed(journal, key, block, block_hash(),
                                         now=NOW)
        self.assertEqual(rebroadcast_block(attempt)["signature"],
                         block["signature"])

    def test_15c_the_journal_passes_the_repositorys_secret_gate(self):
        """The reason long hex is stored in parts rather than verbatim."""
        with tempfile.TemporaryDirectory() as home:
            journal, key, _ = through_broadcast()
            journal, _ = observe(journal, key, {"kind": "received", "at": NOW,
                                                "node": None}, now=NOW)
            write_journal(os.path.join(home, "attempts.json"), journal)
            self.assertEqual(validate.scan_for_secrets(home), [])

    def test_15d_the_stored_block_round_trips_byte_for_byte(self):
        block = signed_block(address())
        packed = retry_safety.pack_block(block)
        self.assertEqual(retry_safety.unpack_block(packed), block)
        self.assertNotIn("d" * 128, json.dumps(packed),
                         "a long hex field was stored whole")
        for part in retry_safety.split_long_hex(block["signature"]):
            self.assertLessEqual(len(part), 32)

    def test_15e_a_nested_block_field_is_covered_too(self):
        nested = {"block": signed_block(address()), "hashes": ["e" * 64]}
        packed = retry_safety.pack_block(nested)
        self.assertEqual(retry_safety.unpack_block(packed), nested)
        with self.assertRaises(Refusal) as caught:
            retry_safety.pack_block({"outer": {"seed_hex": "x"}})
        self.assertEqual(caught.exception.code, "unknown_field")


class ImportGraphTest(unittest.TestCase):
    """Test 16: it cannot reach a node, so it cannot be fooled by one."""

    def test_16_nothing_here_can_reach_the_network(self):
        network = {"socket", "http", "urllib", "ssl", "requests", "asyncio",
                   "ftplib", "smtplib", "xmlrpc", "nanonode"}
        reached = {entry["module"].split(".")[0] for entry in import_graph()}
        self.assertEqual(reached & network, set(),
                         "retry_safety imports a network module")


class ImmutableBindingTest(unittest.TestCase):
    """Hard rule 2: the four fields the binding rests on, and the history."""

    def test_the_four_fields_cannot_move(self):
        journal, key, _ = through_broadcast()
        row = retry_safety.find(journal, key)
        before = json.loads(json.dumps(row))
        for field in IMMUTABLE_FIELDS:
            with self.subTest(field=field):
                after = json.loads(json.dumps(before))
                after[field] = {
                    "payee": other_address(),
                    "idempotency_key": "ik-" + "0" * 32,
                    "amount_raw": "9" * 30,
                    "order_digest_halves": ["b" * 32, "c" * 32],
                }[field]
                with self.assertRaises(Refusal) as caught:
                    retry_safety._assert_binding_held(before, after)
                self.assertEqual(caught.exception.code, "immutable_field")

    def test_history_may_only_grow(self):
        journal, key, _ = through_broadcast()
        row = retry_safety.find(journal, key)
        shorter = json.loads(json.dumps(row))
        shorter["history"] = shorter["history"][:-1]
        with self.assertRaises(Refusal) as caught:
            retry_safety._assert_binding_held(row, shorter)
        self.assertEqual(caught.exception.code, "history_shrank")

    def test_every_observation_is_auditable_afterwards(self):
        journal, key, _ = through_broadcast()
        journal, attempt = observe(journal, key,
                                   {"kind": "timeout", "at": NOW,
                                    "node": "https://node.invalid"}, now=LATER)
        last = attempt["history"][-1]
        self.assertEqual(last["event"], "observed")
        self.assertEqual(last["kind"], "timeout")
        self.assertEqual(last["node"], "https://node.invalid")
        self.assertEqual(last["observed_at"], NOW)
        self.assertEqual(last["at"], LATER)


class AmountsAreIntegersTest(unittest.TestCase):
    """1 XNO is 10**30 raw. A float loses the bottom 13 digits of it."""

    def test_a_float_amount_is_refused(self):
        for value in (1.0e26, 0.5, float(AMOUNT)):
            with self.subTest(value=value):
                with self.assertRaises(Refusal) as caught:
                    open_attempt(empty_journal(), order_digest=ORDER_DIGEST,
                                 amount_raw=value, payee=address(), now=NOW)
                self.assertEqual(caught.exception.code, "bad_amount_raw")

    def test_an_exponent_or_a_decimal_point_is_refused(self):
        for value in ("1e26", "1.0", "+5", "-5", " 5", "0x10", "5²"):
            with self.subTest(value=value):
                with self.assertRaises(Refusal) as caught:
                    open_attempt(empty_journal(), order_digest=ORDER_DIGEST,
                                 amount_raw=value, payee=address(), now=NOW)
                self.assertEqual(caught.exception.code, "bad_amount_raw")

    def test_a_thirty_digit_amount_survives_the_round_trip(self):
        amount = str(10 ** 30)
        journal, attempt = opened(amount_raw=amount)
        self.assertEqual(attempt["amount_raw"], amount)
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            write_journal(path, journal)
            reloaded = read_journal(path)
            self.assertEqual(reloaded["attempts"][0]["amount_raw"], amount)


class BindingForPaymentTest(unittest.TestCase):
    """What a caller on the money path asks before it records a settlement."""

    def test_the_very_block_being_settled_matches(self):
        journal, key, _ = through_broadcast()
        found = binding_for_payment(journal, amount_raw=AMOUNT,
                                    payee=address(),
                                    block_hash=block_hash())
        self.assertEqual(found["matched"]["idempotency_key"], key)
        self.assertEqual(found["blocking"], [])

    def test_a_different_block_for_the_same_payment_is_blocking(self):
        journal, key, _ = through_broadcast()
        found = binding_for_payment(journal, amount_raw=AMOUNT,
                                    payee=address(),
                                    block_hash=block_hash("E"))
        self.assertIsNone(found["matched"])
        self.assertEqual([r["idempotency_key"] for r in found["blocking"]],
                         [key])

    def test_a_terminal_or_unsigned_row_blocks_nothing(self):
        journal, key, _ = through_broadcast()
        journal, _ = observe(journal, key, {"kind": "received", "at": NOW,
                                            "node": None}, now=NOW)
        journal, _ = record_result(journal, key, "https://e.invalid/r",
                                   retrievable="YES", now=NOW)
        found = binding_for_payment(journal, amount_raw=AMOUNT,
                                    payee=address(),
                                    block_hash=block_hash("E"))
        self.assertEqual(found["blocking"], [])

        unsigned, _ = opened()
        self.assertEqual(
            binding_for_payment(unsigned, amount_raw=AMOUNT, payee=address(),
                                block_hash=block_hash("E"))["blocking"], [])

    def test_another_payees_row_is_not_this_payment(self):
        journal, _key, _ = through_broadcast()
        found = binding_for_payment(journal, amount_raw=AMOUNT,
                                    payee=other_address(),
                                    block_hash=block_hash("E"))
        self.assertEqual(found["blocking"], [])
        self.assertIsNone(found["matched"])

    def test_the_payee_is_compared_by_account_not_by_spelling(self):
        """`nano_` and `xrb_` spell one account; a string compare says two."""
        journal, key, _ = through_broadcast()
        legacy = "xrb_" + address()[len("nano_"):]
        found = binding_for_payment(journal, amount_raw=legacy and AMOUNT,
                                    payee=legacy, block_hash=block_hash("E"))
        self.assertEqual([r["idempotency_key"] for r in found["blocking"]],
                         [key])


class TheLoaderChecksTheMatchKeysTest(unittest.TestCase):
    """What a hand-edited journal may say, and what it may not.

    `binding_for_payment` is the only thing standing between a crashed caller
    and a second send, and it matches a row on two keys: `amount_raw` and
    `payee`. It does not report an unparseable one - `same_account` answers
    False for it, so the row is SKIPPED and its signed block stops blocking.
    That is the one direction `binding_for_payment` and `settle.py` both say in
    as many words they must never take: "a false clearance costs a second
    payment to a stranger".

    So these drive the REAL loader over a journal written to disk and then
    assert the money question, not the validator. `self_test`'s `bad_payee`
    control calls `checked_payee` directly, which proves the validator works
    and says nothing about whether the loader uses it - and for one of these
    fields it did not.
    """

    def tamper(self, field, value):
        """A journal through disk, one field rewritten the way an editor would.

        Returns `read_journal`'s answer, or raises the `Refusal` it makes.
        """
        journal, key, _ = through_broadcast()
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            write_journal(path, journal)
            document = json.loads(open(path, encoding="utf-8").read())
            document["attempts"][0][field] = value
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(document, indent=1) + "\n")
            return read_journal(path), key

    def test_an_unparseable_payee_is_refused_rather_than_skipped(self):
        bad = address()[:-1] + ("1" if address()[-1] != "1" else "3")
        with self.assertRaises(Refusal) as caught:
            self.tamper("payee", bad)
        self.assertEqual(caught.exception.code, "bad_payee")

    def test_without_that_check_the_double_pay_guard_goes_quiet(self):
        """The consequence, measured on the loaded journal rather than argued.

        An honest journal blocks. The only difference here is one character of
        a field no state machine compares - and if the loader let it through,
        `blocking` would be empty and `settle.py` would be told that nothing is
        in flight for a request that already carries a signed block.
        """
        journal, key, _ = through_broadcast()
        honest = binding_for_payment(journal, amount_raw=AMOUNT,
                                     payee=address(), block_hash=None)
        self.assertEqual([r["idempotency_key"] for r in honest["blocking"]],
                         [key], "the honest journal must block")

        # The mechanism, asserted where it lives rather than demonstrated by
        # bypassing the loader: `binding_for_payment` reaches the row only if
        # this answers True, and for an unparseable payee it answers False
        # instead of raising. That is the skip, and it is why the refusal has
        # to be at the door - by the time the loop runs, a False here and a
        # genuinely different payee are the same answer.
        self.assertFalse(canonical.same_account("", address()))
        self.assertFalse(canonical.same_account(
            address()[:-1] + ("1" if address()[-1] != "1" else "3"),
            address()))
        self.assertTrue(canonical.same_account(address(), address()))

        with self.assertRaises(Refusal) as caught:
            self.tamper("payee", "")
        self.assertEqual(caught.exception.code, "bad_payee")

    def test_a_block_hash_in_the_other_spelling_is_refused(self):
        """`record_signed` and `binding_for_payment` compare a hash as text.

        Both fail closed on a mismatch, so the cost of the second spelling is a
        refused rebroadcast rather than a second send. A journal that cannot
        hold it at all is the stronger statement and the one this file makes
        for every other field.
        """
        with self.assertRaises(Refusal) as caught:
            self.tamper("block_hash", block_hash().lower())
        self.assertEqual(caught.exception.code, "bad_block_hash")

        for value in (None, 1, block_hash()[:63], block_hash() + "A"):
            if value is None:
                continue
            with self.subTest(value=value):
                with self.assertRaises(Refusal) as caught:
                    self.tamper("block_hash", value)
                self.assertIn(caught.exception.code,
                              ("bad_block_hash", "bad_journal"))

    def test_a_signed_block_whose_hash_is_gone_is_refused(self):
        """The dangerous half of the pair, because nothing else notices.

        `safe_action` still answers BROADCAST_SAME_BLOCK on such a row, so the
        block goes out and the journal cannot name what went out.
        """
        row = through_broadcast()[0]["attempts"][0]
        verdict = safe_action(dict(row, block_hash=None), now=NOW)
        self.assertEqual(verdict["action"], SAFE_ACTIONS[row["state"]],
                         "safe_action does not look at the hash, which is why "
                         "the loader must")
        self.assertIn("REBROADCAST_SAME_BLOCK", verdict["action"])
        with self.assertRaises(Refusal) as caught:
            self.tamper("block_hash", None)
        self.assertEqual(caught.exception.code, "bad_journal")

    def test_a_hash_with_no_block_is_refused_too(self):
        opened_journal, attempt = opened()
        document = json.loads(json.dumps(opened_journal))
        document["attempts"][0]["block_hash"] = block_hash()
        with self.assertRaises(Refusal) as caught:
            retry_safety.checked_journal(document)
        self.assertEqual(caught.exception.code, "bad_journal")
        self.assertIsNone(attempt["signed_block"])

    def test_an_honest_journal_still_loads_unchanged(self):
        """The control. A refusal that also refuses good journals is not a fix."""
        journal, key, _ = through_broadcast()
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            write_journal(path, journal)
            reloaded = read_journal(path)
        self.assertEqual(reloaded, journal)
        self.assertEqual(reloaded["attempts"][0]["idempotency_key"], key)


class CliTest(unittest.TestCase):
    """Exit 0, 2 on a refusal with `reason=<code>`, 1 on an error."""

    def run_cli(self, *argv, home=None):
        return subprocess.run([sys.executable, SCRIPT, *argv],
                              capture_output=True, text=True, cwd=home)

    def test_self_test_is_green(self):
        result = self.run_cli("--self-test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        verdict = json.loads(result.stdout)
        self.assertEqual(verdict["failures"], [])
        self.assertGreater(verdict["negative_controls"], 10)

    def test_the_whole_life_of_a_payment_through_the_cli(self):
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as elsewhere:
            path = os.path.join(home, "attempts.json")
            # The block fixture lives OUTSIDE the directory the secret gate is
            # run over at the end: a serialised block really does carry long
            # hex, which is the whole reason the journal stores it in parts.
            block_path = os.path.join(elsewhere, "block.json")
            with open(block_path, "w", encoding="utf-8") as handle:
                json.dump(signed_block(address()), handle)

            opened_row = self.run_cli("open", "--order-digest", ORDER_DIGEST,
                                      "--amount-raw", AMOUNT, "--payee",
                                      address(), "--now", NOW,
                                      "--journal", path, home=home)
            self.assertEqual(opened_row.returncode, 0, opened_row.stderr)
            key = json.loads(opened_row.stdout)["idempotency_key"]

            for argv in (("signed", key, "--block", block_path,
                          "--block-hash", block_hash()),
                         ("broadcast", key),
                         ("observe", key, "--kind", "confirmed")):
                result = self.run_cli(*argv, "--now", NOW, "--journal", path,
                                      home=home)
                self.assertEqual(result.returncode, 0, result.stderr)

            action = self.run_cli("action", key, "--now", NOW, "--journal",
                                  path, home=home)
            self.assertEqual(action.returncode, 0, action.stderr)
            verdict = json.loads(action.stdout)
            self.assertEqual(verdict["action"],
                             "WAIT_OR_REBROADCAST_SAME_BLOCK")
            self.assertTrue(verdict["blocks_new_send"])
            self.assertEqual(verdict["rebroadcast_block"],
                             signed_block(address()))

            report = self.run_cli("report", "--now", NOW, "--journal", path,
                                  home=home)
            self.assertEqual(json.loads(report.stdout)["in_flight"], 1)
            self.assertEqual(validate.scan_for_secrets(home), [])

    def test_a_second_open_refuses_with_its_code(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "attempts.json")
            argv = ("open", "--order-digest", ORDER_DIGEST, "--amount-raw",
                    AMOUNT, "--payee", address(), "--now", NOW,
                    "--journal", path)
            self.assertEqual(self.run_cli(*argv, home=home).returncode, 0)
            again = self.run_cli(*argv, home=home)
            self.assertEqual(again.returncode, 2)
            self.assertIn("reason=duplicate_open", again.stderr)

    def test_an_unknown_key_refuses(self):
        with tempfile.TemporaryDirectory() as home:
            result = self.run_cli("action", "ik-" + "0" * 32, "--journal",
                                  os.path.join(home, "attempts.json"),
                                  home=home)
            self.assertEqual(result.returncode, 2)
            self.assertIn("reason=no_such_attempt", result.stderr)

    def test_the_table_is_printable_without_a_journal(self):
        with tempfile.TemporaryDirectory() as home:
            result = self.run_cli("table", home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = json.loads(result.stdout)
            self.assertEqual(len(rows), 9)
            self.assertEqual(os.listdir(home), [])


class RuntimeStateIsNotCommittedTest(unittest.TestCase):
    """Hard rule 3: the journal is runtime state, and the tree proves it."""

    def test_the_journal_is_gitignored(self):
        with open(os.path.join(ROOT, ".gitignore"), encoding="utf-8") as handle:
            patterns = [line.strip() for line in handle]
        self.assertIn("attempts.json", patterns)

    def test_validate_fails_if_the_journal_is_tracked(self):
        self.assertEqual(validate.tracked_runtime_state(ROOT), [],
                         "runtime state is tracked in this repository")
        self.assertIn("attempts.json", validate.RUNTIME_STATE)

    def test_git_does_not_track_it(self):
        result = subprocess.run(["git", "ls-files", "attempts.json"],
                                cwd=ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            self.skipTest("no git here")
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
