# paid-work-queue — audit, 2026-09-27

First audit of this repository. Read in full: `validate.py`, `vendor/money.py`,
`vendor/nanoaddr.py`, `schema/*.json`, `jobs.json`, `receipts.json`, the CI
workflow and both test files.

## What was checked, and how

Baseline before any change, all green: `python3 -m unittest discover -s tests`
(39 tests), `python3 e2e_check.py` (20/20), `python3 validate.py` on the
committed tree, and the workflow's stats.json-is-not-stale step.

**The address codec was the first thing checked**, because the module docstring
says an outside agent's payout address once failed checksum and nothing caught
it. `vendor/nanoaddr.py` was tested against five real mainnet addresses,
including two accounts the swarm actually holds and the all-zero burn account:
all five validate and round-trip through `encode(decode(a))` character for
character, the `xrb_` form of one normalises back to the same `nano_` address,
and a one-character alteration is refused as `bad_checksum`. The 4-pad-bit rule
(`body[0] in "13"`) is correct and is what makes the 52-character body decode
soundly. No defect found here.

`vendor/money.py` is integer-only as it claims; no float is reachable from any
money path in this repository.

## Fixed

**`_rfc3339` accepted dates that do not exist** (`validate.py:122`). The check
was `1 <= month <= 12 and 1 <= day <= 31`, so `2026-02-31T00:00:00Z` matched the
pattern, passed the range, and was returned as a valid timestamp — meaning a job
could be merged with `posted` or `expires` on a day that never comes, and a
receipt could carry an impossible `settled_at`. `2026-02-29`, `2026-04-31` and
`2026-06-31` behaved the same way. Replaced with a real calendar check via
`datetime.date`, which also keeps month validation. `second == 60` is still
accepted on purpose: RFC3339 permits a leap second, and `datetime` would not.

Proved by `test_impossible_calendar_dates`, which fails against the old range
check (`AssertionError: (2026, 2, 31, 0, 0, 0) is not None`) and passes after,
plus `test_real_dates_including_a_leap_day_are_accepted`, which pins 2024-02-29
and the leap second so the fix cannot be tightened into refusing real times.

## Found, not fixed — needs an owner decision

**The README points a public reader at a private repository.** `README.md:59`
links to `dhyabi2/swarm-decisions` as the source of truth for the vendored money
helpers, and `vendor/money.py:6` names it too. That repository is private, so
every reader of this public README gets a 404 on the one link that explains
where the money code came from. Not changed here because the fix is a choice
only the owner can make — publish that repository, or drop the link and keep the
provenance sentence. Nothing about the vendored code depends on the answer: it
is self-contained, exactly as its docstring says.

**`cross_check` compares raw amounts as strings, not integers**
(`validate.py:361`): `receipt.get("amount_raw") != job.get("price_raw")`. The
file's own docstring says money is compared as integer raw. A receipt whose
`amount_raw` is written `"0250000000000000000000000000000"` is numerically the
price and passes `_check_price` on both sides, but is then rejected with a
message naming two amounts that are the same number. It fails safe — a wrong
amount can never pass this way, because string equality is stricter than integer
equality on digit strings — so this is a confusing false failure, not a payment
risk. Left for a human because it is the money comparison in a settlement gate,
which is not a line an automated audit should move on its own.

## Looked at and deliberately not changed

- **The append-only check fails open.** `receipts_at_ref` returns `None` when
  `git show <base>:receipts.json` cannot be read, and `run` then prints a note
  and exits 0 — so on any run where the base commit is not in the checkout, the
  append-only gate is skipped rather than failing. That is deliberate (the
  workflow sets `fetch-depth: 0` to make it work, and a first commit has no
  base), and turning it into a hard failure would break legitimate runs. Worth
  knowing that a green CI does not by itself prove the append-only check ran.
- **Two receipts may name the same `job_id`, and a receipt may exist for a job
  that is not yet `settled`.** Both look like gaps at first read, and both are
  the repository's intended flow: the block hash is written into the receipt
  before the job's state changes, and a mistake is corrected by appending a new
  receipt rather than editing one. Reported as findings they would have been
  wrong.

## Not found

No secret, key or seed in the tree or in `git log -p`. No dependency of any kind
(standard library only, vendored helpers). No unchecked input reaching a shell:
the one `subprocess` call passes a fixed argument list, never a shell string.
