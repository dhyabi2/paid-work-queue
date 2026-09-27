# paid-work-queue — audit of claim.py and settle.py, 2026-09-27

The first audit (`paid-work-queue-2026-09-27.md`) read `validate.py`,
`vendor/money.py`, `vendor/nanoaddr.py`, the schemas and both test files. It
predates this pair: `claim.py` landed at 06:36Z and `settle.py` at 06:47Z, after
that audit was written. **Nobody had read them.** This is that read.

## What was checked, and how

Baseline at `c632079`, all green before any change: `python3 -m unittest
discover -s tests` (83 tests), `python3 e2e_check.py` (20/20), `python3
validate.py` on the committed tree. That baseline is also the first
verification these two commits have had.

`vendor/money.py` re-read: integer-only, no `Decimal`, no `scaleb`, so the
defect fixed in `nano-work-queue` on 2026-09-27 does not exist here.
`vendor/nanoaddr.py` re-read: the 4-pad-bit rule (`body[0] in "13"`) is correct,
and the checksum is blake2b-5 reversed as the spec says.

Three things that look like defects and are not, checked before reporting them:

- **One block cannot pay two receipts.** `settle.py` only refuses a *job* that
  is already settled, so the same `--block-hash` can reach a second job with the
  same payee and price. `validate.py:320` catches it ("one block pays one
  receipt"), and `settle.py` runs `validate.run` inside the try block and rolls
  every file back when it fails. Defence in depth, working.
- **`claim.py` never checks `--handle` for a key.** `HANDLE_RE` admits 64 hex
  characters, so a seed passed as a handle would be written to `jobs.json`.
  `validate.py`'s secret gate refuses that tree-wide, and `settle.py` checks
  `claimed_by` too. Worth knowing the file-writing step is not itself the gate.
- **`str.isdigit()` in `xno_to_raw` admits non-ASCII digits.** `int()` then
  parses them to the same value, so no amount is misread.

## Fixed

**`settle.py` refused a correctly-paid job when the payee was spelled `xrb_`.**
`interrogate` compared the node's `link_as_account` against the job's
`payout_address` as strings. One account has two spellings: `nano_…` and the
legacy `xrb_…`. `vendor/nanoaddr.py` accepts both by design (`PREFIXES`), the
receipt schema's own pattern is `^(nano|xrb)_…`, and `claim.py` stores whatever
the claimant gave, verbatim. A node always answers in `nano_` form. So a
claimant who gave the `xrb_` spelling produced a job that **could never be
settled** — and the refusal arrives *after* the operator has irreversibly sent
the money:

```
block A1B2…A1B2 paid nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3,
but job job-1 is owed xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3
- refusing
```

Identical 60-character bodies; identical public key. The seller is paid and has
no receipt, and the only recovery is the hand-edit of `jobs.json` that `claim.py`
exists to abolish. It failed safe — nothing was written — which is why a green
suite never noticed: no test used the `xrb_` form.

`interrogate` now compares the public keys the two addresses decode to, which is
what the chain means by "the same account". `account_key()` returns `None` for
anything that is not an address, and a `None` on either side still refuses, so a
block with no destination is rejected exactly as before.

**And, necessarily in the same change:** `sellers_paid` in `compute_stats` is
`len({r["paid_to"] for r in receipts})` — a set of strings. Before the fix an
`xrb_` receipt could not exist, so the counter was correct by accident. Fixing
the comparison alone would have made one seller who spelled their address both
ways count as two. Receipts now record `canonical(address)`, the `nano_` form,
so the counter stays right. `cross_check` does not compare `paid_to` against
`payout_address`, and the schema pattern admits `nano_`, so nothing else moves.

Pinned by four tests. `test_18` and `test_18b` fail against the previous code
(`AssertionError: 9 != 0`); `test_18c` proves the fix did not loosen the check
into accepting a stranger, in either spelling, and `test_18d` keeps a block with
no destination refused. 87 tests, 20/20 e2e, `validate.py` green, and
`jobs.json`/`receipts.json`/`stats.json` byte-identical.

Verified end to end through the real CLIs against a loopback HTTP node, not the
injected fake: `claim.py --address xrb_…` → `settle.py --node http://127.0.0.1:…`
→ exit 0, `paid_to` canonical, `sellers_paid=1`, tree passes `validate.py`. The
same script against the previous `settle.py` exits 9.

## Found, not fixed — still needs an owner decision

Both findings from the first audit stand, unchanged and still unowned: the README
links a public reader to a **private** repository (`README.md:59`), and
`cross_check` compares raw amounts as strings (`validate.py:361`). Neither was
touched here.

**New, and deliberately left:** a receipt added **by hand** in `xrb_` form would
still be counted as a separate seller, because only receipts `settle.py` writes
are canonicalised. Fixing that means counting by public key inside
`compute_stats` — a line in a settlement gate, and the first audit's reasoning
for leaving such a line to a human applies unchanged.
