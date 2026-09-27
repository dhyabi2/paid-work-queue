# paid-work-queue — audit of the amount comparison and `nanonode.py`, 2026-09-27

Third audit of this repository, and the one the second predicted. The second
audit (`paid-work-queue-2026-09-27-settle.md`) fixed a payee check that compared
two spellings of one account, and closed with a generalisation:

> wherever this family compares two identifiers for equality, check whether the
> identifier has more than one valid spelling. Addresses do (`nano_`/`xrb_`);
> amounts do (`_check_price`'s leading zeros, the finding the first audit left
> for a human); hashes do (upper/lower, which `settle.py` already normalises).
> Two of those three were live defects.

The third one was a live defect too. This is that read.

## What was checked, and how

Baseline at `b0a06d4` (the second audit's fix, still unmerged on a branch), all
green before any change: `python3 -m unittest discover -s tests` (87 tests),
`python3 e2e_check.py` (20/20), `python3 validate.py` on the committed tree. The
87 tests were also re-proved to fail at `c632079` on `test_18`/`test_18b`
(`9 != 0`), confirming that branch's fix is real and not merely asserted.

**Hashes were checked first and are not a defect.** `settle.py:335` does
`block_hash = block_hash.upper()` before `interrogate` is reached, so the
uppercase normalisation in `FakeNode.block_info` is redundant rather than a
fixture/production divergence. The third spelling was already handled.

## Fixed: a price written with a leading zero could never be settled

`interrogate()` compared the amount the node reported against the job's price
**as text**:

```python
amount = str(answer.get("amount"))       # from the node: "250000...", always canonical
expected = str(job["price_raw"])         # from jobs.json: whatever was typed
if amount != expected:                   # "250000..." != "0250000..."
    raise Refused(EXIT_MISMATCH, ...)
```

Raw is an integer, and an integer has more than one spelling. `"0250…"` and
`"250…"` are the same 0.25 XNO. **A padded price is a valid tree**, which is what
makes this reachable rather than theoretical: `_is_positive_int_string` accepts
`"0250…"` (`str.isdigit()` is true), and `_check_price` compares the XNO and raw
fields with `int()`, so `validate.py` passes the job and CI merges it. A node
always answers the canonical form. So the two disagreed as strings while naming
one amount, and the refusal arrives *after* the buyer has irreversibly sent the
money:

```
block A1B2…A1B2 paid  250000000000000000000000000000 raw,
job job-1 is priced at 0250000000000000000000000000000 raw - refusing
```

Identical amounts, one leading zero. The seller is paid and cannot be given a
receipt, and the only recovery is the hand-edit of `jobs.json` that `claim.py`
exists to abolish. It is the same failure shape as the payee bug, in the other
field of the same comparison block.

**Why it hid.** It fails *safe* — nothing is written — so it can never surface as
a bad receipt, only as a refusal nobody was there to see. And all 87 tests were
green because **not one of them used a padded price**: every fixture builds its
price from the canonical `PRICE_RAW` constant.

**The fix is two coupled halves, and both were proved load-bearing.**
`validate.py:367` cross-checked the receipt against the job with
`receipt["amount_raw"] != job["price_raw"]`, also as text. Fixing only
`interrogate` makes `settle.py` write a canonical receipt against a padded
price, `validate.py` then rejects the tree, and because `settle.py` runs
`validate.run` inside its transaction the whole settlement rolls back:

```
FAIL receipts.json: receipt-001 paid '250000000000000000000000000000' raw
for job job-1, which is priced at '0250000000000000000000000000000' raw
  1 failure(s). Nothing was merged.
```

So: `raw_amount()` compares the integers in `interrogate`, `canonical_raw()`
writes the canonical spelling into the receipt, and `_same_raw()` makes
`validate.py`'s cross-check numeric. This mirrors the payee fix exactly —
compare the value, record the canonical form — and for the same reason: a
downstream string comparison is only safe when one spelling exists.

## Verification

- **92 tests** (5 new). `test_19` fails against the pre-fix code with `9 != 0`,
  naming two identical numbers that differ by one leading zero.
- **Both halves mutation-checked red**: reverting `validate.py` alone fails
  `test_19` with the rollback above; reverting `settle.py` alone fails it with
  the original refusal.
- **Four guard tests** that the fix does not loosen the amount check: a genuinely
  short payment (`19c`), a non-numeric amount from the node (`19d`), a padded
  price against a short payment (`19e`), and the ordinary canonical case
  unchanged (`19b`). All four pass before *and* after — they guard, they do not
  prove.
- `python3 e2e_check.py` **20/20**; `python3 validate.py` on the committed tree
  OK; `jobs.json`, `receipts.json`, `stats.json` and `schema/` **byte-identical**
  to `b0a06d4`.
- **A real socket**, which the suite deliberately never opens: the real
  `settle.py` CLI driven against a loopback `http.server` acting as a Nano node,
  through `nanonode.HttpNanoNode`. **Exit 9 before the fix, exit 0 after**, the
  receipt carrying `amount_raw: 250000000000000000000000000000` and
  `paid_xno_total: 0.25`. This is the only exercise `HttpNanoNode` has ever had.

## `nanonode.py` — read in full, no defect found

Named in neither previous audit, and it is the file every trust decision in
`settle.py` rests on. The custody claim holds: one RPC (`block_info`), nothing
that can send, sign or unlock, and `interrogate` checks `error`, then
`confirmed == "true"`, then `subtype == "send"`, then payee, then amount,
refusing on each. Two things were checked and are **not** defects:

- **A non-HTTP URL fails closed.** `urllib` will open any scheme it supports, so
  `file:///…` is genuinely read rather than rejected on sight — but the body is
  not JSON, so it raises `NodeError("the response was not JSON")` and discloses
  nothing. The URL is the operator's own `--node` flag, not attacker input, so
  this is a typo that fails safe, not an attack path.
- **`response.read()` has no size cap**, so a hostile or broken node could
  answer with an unbounded body. Worth a `read(limit)` if this ever points at a
  node the operator does not run; left alone here because it is out of this
  change's scope and the brief asks for one concern per change.

## Still outstanding, and not ours

`b0a06d4` (the payee fix) and this change are both on branches. A push to `main`
of this repository is refused by the cloud worker's own auto-mode classifier as
`[Merge Without Review]` — twice now, on two consecutive runs. This branch is
built **on top of** `b0a06d4` rather than beside it, so one human merge lands
both money fixes. Until it lands, `main` still refuses a correctly paid job in
both of these two ways.
