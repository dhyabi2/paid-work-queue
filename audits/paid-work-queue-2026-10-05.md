# paid-work-queue - audit 2026-10-05

Lens: can an agent pay, or be paid, in XNO with this code today without being hurt. Last
audited 2026-10-03, which found nothing; since then #5 to #10 landed six new modules
(`counterparty_role.py`, `jobs_feed.py`, `divergence_note.py`, `order_bound_amount.py`,
`outcome_descriptor.py`, `external_edge_count.py`), so this pass starts on the surface
that audit never saw.

**One defect found and fixed**, plus one authorisation finding reported without a patch
because every candidate fix is a decision about the published API rather than a repair.

## Checked

Before anything was touched:

- `python3 -m unittest discover -s tests`: **823 tests, OK.**
- `python3 e2e_check.py`: **21/21 checks pass.**
- `python3 -m py_compile *.py tests/*.py`: clean.
- `python3 validate.py --no-write-stats`: `OK jobs_open=3 jobs_settled=0 sellers_paid=0
  paid_xno_total=0 XNO`.
- Every `--self-test` the README advertises, run rather than read: `custody_probe`,
  `authority_receipt`, `fulfillment_receipt`, `order_bound_amount`, `outcome_descriptor`,
  `external_edge_count`, `counterparty_role`, `divergence_note`, `jobs_feed`, `grant_mint`,
  `x402_binding`, `independent_confirm` - all exit 0. Every `--vectors` the README
  advertises (`order_bound_amount`, `outcome_descriptor`, `external_edge_count`) exits 0.
- The first step a new agent takes: `python3 claim.py --list` prints the three open jobs at
  0.25 / 0.15 / 0.05 XNO expiring 2026-10-17, and the README's `derive` line runs as
  written (`python3 order_bound_amount.py derive --order-digest <hex64> --amount-raw
  1000000000000000000000000000` -> `pay_raw` with a derived tag).
- **Where the destination of a send is read.** Every module that grades a block was checked
  against the shape a node actually answers with. `settle.py:239`, `authority_receipt.py:286`,
  `counterparty_role.py:264` and `independent_confirm.py:324` all read
  `contents.link_as_account`; the README itself tells an agent to read
  `contents.link_as_account` (README:563). `x402_binding.py` did not. That is the defect
  below.
- **Amounts.** No float touches an amount anywhere on the path. `vendor/money.py`,
  `claim.format_xno`, `canonical.raw_amount`, `order_bound_amount.checked_amount`,
  `external_edge_count._raw`, `x402_binding._amount_of` and
  `independent_confirm._read_amount` are integer-only and refuse rather than coerce.
  `quotelock.py` is the only `decimal` user and it never runs in the process-global
  context: `_quantise` and `amount_raw_for` both open `localcontext()` and set
  `ctx.prec = 60` (`quotelock.py:177`, `quotelock.py:210`), which is above the 39 digits
  of the whole supply, so no 31-to-39-digit raw value is rounded at prec=28. The two
  `float()` calls in `external_edge_count.py:511` and `:536` are on a *share* - a ratio
  between 0 and 1 - and never on an amount of raw.
- **`order_bound_amount.py`'s one unproved-looking claim**, that "one `pay_raw` may be
  derived by only one non-colliding order, by construction" (`order_bound_amount.py:290`):
  it holds. Prices are forced to be multiples of the modulus and the tag is in
  `1 .. m-1`, so equal `pay_raw` implies equal tag, and equal tags are excluded as a
  collision before matching. The dict comprehension that would otherwise silently drop one
  of two orders cannot be reached.
- **Double settlement.** `settle.check_job_is_settleable` refuses any job that already has a
  receipt, refuses a job not in `claimed`, refuses a `payout_address` that fails its
  checksum, and refuses a `price_raw` that is not an integer string - all before the node
  is asked anything. The destination is compared by account and the amount as an integer.
- **Double claiming.** `http_claim.claim` holds one lock across read, decide and write;
  `_live_claim_for` expires a lapsed claim and reopens the job in the same pass; and
  `_external_hold` refuses a job claimed through the pull-request path rather than
  overwriting the first claimant's `payout_address`.
- **Secrets.** Nothing secret-shaped in the tree or in the 39 commits of history; no `.env`,
  key, seed or wallet file has ever been added. `operator_accounts.json` carries an empty
  declared set with a note saying why.

## Found

### 1. `x402_binding.verify` refused a payment that arrived (fixed)

`x402_binding.py:395` read the destination of the send as
`block.get("link_as_account")` - the top level of the block only.

A Nano node's `block_info` answer with `json_block=true` nests the signed block under
`contents`, so `link_as_account` is *not* a top-level field of a real answer. Every other
field `verify` reads (`amount`, `confirmed`, `subtype`, `local_timestamp`,
`block_account`, `hash`) is exactly where the node puts it, so the block this module
expects is a node's own answer in every respect but one - and for that one field it looked
in the wrong place.

Concretely, with the module's own control tuple and a block that differs from its control
only in carrying the destination where a node carries it:

```
FLAT  : {"ok": true,  "reasons": []}
NODE  : {"ok": false, "reasons": ["pay_to_mismatch"],
         "observed": {"link_as_account": null, ...}}
```

A confirmed send, of exactly the required raw, to exactly the quoted address, graded as
`pay_to_mismatch`: the x402 payer is told their correct payment does not bind. This is on
the money path and it is the one refusal the module's own docstring says it must never
issue ("refusing it would refuse a payment that arrived").

It survived because the module's negative controls and all 60 of its unit tests build a
*flattened* block (`x402_binding.py:517`, `tests/test_x402_binding.py:72`), a shape no node
answers with - while the control fixtures of `authority_receipt.py:585`,
`counterparty_role.py:585`, `fulfillment_receipt.py:854`, `grant_mint.py:583` and
`independent_confirm.py:608` all nest it.

### 2. The release credential is published by the service itself (reported, not patched)

`http_claim.release` (`http_claim.py:676`) authorises a release by matching the `payee`
the caller sends against the payee recorded on the claim, and says so: *"matching it is
the only credential there is."* That value is public:

- `list_jobs` mirrors every field of the job (`http_claim.py:455`), and `_attach_to_job`
  writes `payout_address` and `claim_url` onto the job (`http_claim.py:744`, `:746`), so
  `GET /unstuck/api/v1/jobs` hands a stranger both the claim id and the credential;
- `public_claim` returns `payee` as well (`http_claim.py:429`), and the README calls that
  URL one "anyone can read without a credential";
- `claims.json` is published as "the public record of who claimed what and when".

Run against a clean copy of this clone:

```
claim:                201 clm_d20904a2
board claim_url      : http://localhost:8080/unstuck/api/v1/claims/clm_d20904a2
board payout_address : nano_1hsz9wzmyhsz9wzmyhsz9wzmyhsz9wzmyhsz9wzmyhsz9wzmyhszamq8hig1
stranger DELETE ->    200 {'state': 'released', 'job_state': 'open'}
claim state now:      released
```

So any stranger can release any live HTTP claim, including one already in `delivered`, and
then claim the job themselves - which rewrites the job's `payout_address` to their own. An
agent that is mid-work, or that has already published its work, loses the hold on it and
the operator's next settlement pays whoever claimed last.

No patch is proposed, deliberately. Hiding the value does not close it (the same address is
in `claims.json` and in `jobs.json`, both published on purpose), and anything that would
close it - a secret handed back at claim time, or narrowing release to the `open` state and
taking "hand it back" away from a seller who has delivered - changes the published API and
the data model. That is the maintainer's decision, not a repair, and it does not belong in
a fix branch.

`deliver` (`http_claim.py:591`) checks no credential at all, so the same published claim id
also lets a stranger overwrite the `delivery_url` and `note` of a claim they do not hold.
Adding the payee check there would contradict the README's own `deliver` transcript, which
sends only a `url`. Same decision, same reason.

## Fixed

Branch `fix/x402-block-destination`, two files.

- `x402_binding.py`: a `_destination(block)` helper that reads `contents.link_as_account`
  when the node nests it and the top level otherwise - the same precedence
  `authority_receipt._block_destination` and `counterparty_role.block_destination` already
  use - and `verify` calls it. Deliberately *not* gated on `subtype`, unlike its siblings,
  because a block that is not a send has its own reason code here and folding it into
  `pay_to_mismatch` would report two refusals for one defect; `block_wrong_subtype` still
  comes back alone.
- `tests/test_x402_binding.py`: a `node_block()` fixture that moves the destination to
  where a node puts it and nothing else, test 12c (a node-shaped block verifies, and the
  verdict echoes the destination it found) and test 12d (a nested stranger is still
  refused, so the new read cannot pass everything).

The change only widens where one field is *looked for*. It changes no amount, no
destination, no rounding and no key path, and it adds no new acceptance: a block whose
nested destination is the wrong account is refused exactly as before.

Before (test present, fix absent):

```
Ran 62 tests in 0.518s
FAILED (failures=1)
AssertionError: False is not true : ['pay_to_mismatch']
```

After: `Ran 62 tests in 0.541s / OK`; whole suite `Ran 825 tests / OK`; `e2e_check.py`
21/21; `py_compile` clean; `x402_binding.py --self-test` exit 0 with 11 negative controls
and no failures.

## Could not verify

- **No live node and no XNO moved.** That `block_info` nests `link_as_account` under
  `contents` is established from this repository's own four other readers of that field and
  from the README's own instruction (README:563), not from a node's answer: the container
  has no route to a public Nano RPC. If a proxy in front of a node flattens the answer, the
  fix still reads it - that is why the top-level read was kept as the fallback.
- **The module's own controls still only exercise the flattened block.**
  `x402_binding._control_block` (`:517`) was left alone to keep the change minimal, so
  `--self-test` does not cover the node shape; the two new unit tests do.
- **The hosted surface.** `https://getunstuck.space` is still not live, as the README says,
  so the HTTP findings above are against `http_claim.py` in this clone only.
- **`https://nanolooker.com/block/<hash>`**, the explorer every receipt points a stranger
  at: still denied by the container's network policy, so "checkable by a stranger" remains
  established from the receipt's shape rather than by following the link.
- **`quotelock.amount_raw_for` at absurd magnitudes.** prec=60 covers every real amount;
  a `usd` figure with more than about forty integer digits would round, and `quote` and
  `check_quote` would round identically, so no disagreement is reachable. Not pursued
  further.
