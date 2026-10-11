# paid-work-queue — audit 2026-10-11

Lens: can an outside seller get paid in XNO here today, and can a stranger check that it happened,
without being hurt.

## Checked

- Baseline on `main` (`0bab203`), every step the CI workflow runs: `python3 -m unittest discover -s
  tests` **1112 passed, 1 skipped**; `python3 e2e_check.py` **36/36**; `python3 validate.py
  --no-write-stats` **OK**; `verdict.py check` and the byte-identical rebuilds of
  `feed/verdict.json` and `feed/rpc.json`; `proof_without_execution.py --self-test`; the outbound
  draft lint.
- `vendor/money.py`: `xno_to_raw` / `raw_to_xno` are integer-only, refuse a negative, refuse more
  than 30 decimal places, and scale by digit-string padding. No float on the money path anywhere in
  the tree.
- `settle.py` end to end, the only path that records a payment:
  - `check_job_is_settleable` refuses a second receipt for a job, a job not in `claimed`, a missing
    or checksum-failing `payout_address`, a missing `claim_url`, and a non-integer `price_raw`.
  - `consult_retry_journal` refuses when `attempts.json` says a *different* send for the same
    (amount, payee) may already be in flight, and treats an unreadable journal as a refusal rather
    than an absence — the double-pay case.
  - `interrogate` asks one node one question and raises on every disagreement: unknown block,
    unconfirmed, wrong subtype, wrong destination (`same_account`, by account rather than by
    spelling, so an `xrb_`-spelled job is not refused for a payment that arrived) and wrong amount
    (`same_amount`, by integer value).
  - `expected_payee` from the claim must be the same account as the job's payout address before
    anything is written.
  - The write is snapshot-and-restore, and `validate.run` is executed over the settled tree before
    the write is allowed to stand, so a settlement CI would reject never lands.
  - One block cannot pay two receipts: `validate.py:413` collects `block_hash` across receipts and
    refuses a duplicate ("one block pays one receipt"), and because `settle.py` runs `validate.run`
    over its own output, the same-hash-for-two-jobs case is caught and rolled back rather than
    merely caught in CI. Confirmed by reading both sides.
- `nanonode.py` is the only module permitted to open a socket, it implements `block_info` and
  nothing else, and `tests/test_settle.py` walks the import graph to keep it that way.
- The secret gate in `validate.py` (a committed 64-hex run is refused because a seed looks exactly
  like one, with `block_hash` the single documented exception) and the digest-halves convention it
  forces on `feed/PINS.json` and the verdict artifact. No secret in the working tree.
- `feed/verdict.json`'s 10 claims: every `measured` one rechecks from the artifact's own bytes
  (`missing_inputs()` empty, `check()` opens no file), and all 15 URLs it publishes were fetched
  this run. Fourteen answered 200. The fifteenth is below.

## Found and fixed

**The row about checking us without us pointed a stranger at a 404.** `verdict.py:597` built
`order-is-in-the-amount`'s `check_without_us` as `[RAW + "vectors/", RAW +
"order_bound_amount.py"]`. `raw.githubusercontent.com` serves blobs only and answers 404 for a path
ending in a slash. Measured 2026-10-11:

```
404  https://raw.githubusercontent.com/dhyabi2/paid-work-queue/main/vectors/
200  https://raw.githubusercontent.com/dhyabi2/paid-work-queue/main/vectors/order-bound-amount-v1.json
```

It was the only unfetchable URL in the artifact, and it was first in the list, in the one row whose
subject is a stranger rechecking the order-to-amount binding without running our code. The README
calls `check_without_us` "the raw URLs behind it"; a 404 there spends an agent's one unit of
patience at exactly the moment the file is asking for trust.

The row now names the vector file its own recipe needs. A new law —
`test_1b_every_check_without_us_url_names_a_file_in_this_tree` — resolves every `check_without_us`
URL of every claim against the working tree and refuses a directory, a missing path or a URL that
is not a raw URL of this repository. It is offline by construction, so it holds in CI and in a
fork, and it fails without the change with the 404 URL named in the assertion message.

`feed/verdict.json` and `feed/rpc.json` are rebuilt and both recheck; the rebuild at the committed
`generated_at` is byte-identical, as CI requires. `feed/PINS.json` is re-pinned in its own commit,
the way `#18`/`#19` established, because any edit to a pinned source turns test 11 red until it is.
Suite after the change: **1113 passed, 1 skipped**, 36/36 e2e, validate OK.

## Could not verify

- No real Nano node was contacted; `FakeNode` answered every `block_info` in the suite, as the
  design intends.
- `feed/PINS.json` now pins at this branch's commit. The repository's own convention (`#19`, "Re-pin
  the digests at the commit on main, not the branch's") is to re-pin at the merge commit once this
  lands; that follow-up is a separate one-file change and is not in this pull request.
- The seller-facing claim path (`claim_by_issue.py` driven by the GitHub workflow) was read, not
  exercised against a live issue event.
