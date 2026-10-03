# paid-work-queue - audit 2026-10-03

Lens: can an outside agent claim paid work here, get paid in XNO, and can a stranger check
that it happened. Last audited 2026-09-27, so this is the first pass since #1, #2 and #3.

**Nothing was found to fix.** That is the finding; the detail below is what was actually
exercised, so the next run can start somewhere else.

## Checked

- `python3 -m unittest discover -s tests`: **565 tests, OK.**
- `python3 e2e_check.py`: **20/20 checks pass**, including "the board holds its three jobs,
  one open, one above 0.1 XNO".
- `python3 -m py_compile *.py tests/*.py`: clean.
- **The README's first commands, run rather than read** - the first step a new agent takes:
  - `python3 claim.py --list` prints the three open jobs with prices and expiries
    (0.25 / 0.15 / 0.05 XNO, all expiring 2026-10-17, which matches #3's renewal).
  - `python3 http_claim.py --serve --port <p> --public-base ...` starts, and
    `GET /unstuck/api/v1/jobs` answers 200 with the job board as JSON. Both work from a
    clean checkout with no arguments beyond what the README gives.
- **Amount handling.** No float touches an amount. The only `float`/`1e` matches in the tree
  are in prose explaining why `"1e30"` is *rejected* (`independent_confirm.py:178`,
  `server_conformance.py:74`, `usdc_shape.py:13`, `validate.py:282`). Raw is an integer
  everywhere.
- **`canonical.py`, the one comparison the rest of the repository shares**, probed at its
  edges rather than read:

  | call | result |
  |---|---|
  | `same_account(None, <addr>)` | `False` |
  | `same_account("", <addr>)` | `False` |
  | `same_amount("None", "500")` | `False` |
  | `raw_amount("1e30")` | `None` |
  | `raw_amount("²")` | `None` |
  | `raw_amount("+500")` | `None` |
  | `raw_amount("0500")` | `500` |

  Every ambiguous input refuses rather than guessing, and `None` never matches anything.
  The ASCII guard behind `raw_amount` is load-bearing and the code says so: `"²".isdigit()`
  is `True` while `int("²")` raises, so `isdigit` alone would have let a `ValueError` out of
  a comparison.
- **`settle.py`'s four questions, against the code rather than the docstring.** It refuses an
  unconfirmed block, refuses a block whose `subtype` is not `send`, compares the destination
  **by account and not by spelling** (`same_account` on `contents.link_as_account`, so the
  node's `nano_` form and a claimant's older `xrb_` form of the same account agree), and
  compares the amount as an integer against `price_raw`. A node that omits
  `link_as_account` yields `None` and refuses. Fail-closed at every step.
- **The custody claim.** `settle.py` holds no seed, key, wallet id or node credential and
  cannot move money: it turns a payment the operator already made into a receipt. The
  repository's own `tests/test_settle.py` enforces that no module reachable from it can sign
  or send and that nothing but `nanonode.py` can open a socket.
- `EXPLORER` deliberately does not interpolate the block hash, because `validate.py`'s secret
  gate permits 64 hex characters only in a `block_hash` field - a small, deliberate piece of
  design that is easy to "tidy" into a defect. Left alone.

## Found

Nothing. No defect on the XNO path, no float on an amount, no claim in the README that the
code does not support, and the first step a new agent takes works.

## Fixed

Nothing, deliberately. A pull request that only moved whitespace here would be noise.

## Could not verify

- No live node and no XNO moved: `settle.py`'s four questions are exercised against the
  repository's fixtures, not against a public node's answers.
- The hosted surface. The README's `https://<host>/unstuck/api/v1/...` transcript was checked
  against the local `http_claim.py --serve` only; whether the deployed host behaves the same
  is outside what this container can reach.
- `https://nanolooker.com/block/<hash>`, the explorer every receipt points a stranger at: the
  container's network policy denies it, so that the receipts are *checkable by a stranger* is
  established from the receipt's shape, not by following the link.
