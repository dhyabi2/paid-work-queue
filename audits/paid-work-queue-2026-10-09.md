# paid-work-queue — audit 2026-10-09

Same lens: can an agent pay, or get paid, in XNO with this code today without being hurt?

## What I checked

Baseline on `main` (`a95ed85`), every command CI runs:

```
python3 -m unittest discover -s tests   # Ran 1099 tests — OK (skipped=1)
python3 e2e_check.py                    # 36/36 checks pass
python3 validate.py --no-write-stats    # OK  jobs_open=3  jobs_settled=0
python3 verdict.py check                # ok: true, rechecked 10
```

- **`settle.py`'s four questions** (`:299-328`). This module gets the settlement discipline
  right, and it is worth recording because the same check was missing elsewhere today: it
  refuses unless the node says `confirmed` is `"true"` (`:299`), unless `subtype` is `send`
  (`:305`), unless the destination matches the claimant's address through `same_account`
  (`:314`), and unless the amount equals `price_raw` exactly through `same_amount` (`:324`).
  It holds no seed, key or node credential and cannot move money.
- **Money arithmetic.** Grepped every amount path for `float(`, `1e30`, `getcontext` and bare
  `Decimal`. Raw is an integer everywhere it decides anything. `quotelock.py` does its one
  conversion inside `localcontext()` at 60 digits (`:177`, `:210`) rather than the process
  default — the `prec=28` defect class open across four sibling repositories is **not present
  here**. The two `float()` calls on the XNO path (`retry_safety.py:1002,1010`,
  `external_edge_count.py:502`) are on an hours TTL and a share ceiling, not on an amount.
- **Shell and path handling.** No `os.system`, no `shell=True`, no `os.popen` anywhere.
  `subprocess` appears only in `e2e_check.py`, always list-form, never with caller text.
- **`x402_binding.py`, `http_claim.py`, `claim_by_issue.py`, `canonical.py`, `nanonode.py`,
  `vendor/money.py`** read end to end for an acceptance that should be a refusal.
- **`independent_confirm.py`** (814 lines) — the finding below.

## What I found and fixed

**One node asked three times was a quorum of three.**

`decide()` counted *responses*, not nodes. `agreeing` was `sum(1 for n in per_node if
n["verdict"] == "agree")` and nothing anywhere compared one endpoint against another. So three
copies of one endpoint — or three spellings of one host — met the default quorum of three and
returned `confirmed_independently: true` with `reasons: []`. Measured on `main`:

```
THREE COPIES OF ONE ENDPOINT -> confirmed_independently: True
  nodes_total=3 agreeing=3 reasons=[]
THREE SPELLINGS OF ONE HOST  -> confirmed_independently: True
  agreeing=3 reasons=[]
```

(`https://rpc.onehost.example`, `https://rpc.onehost.example/`, `HTTPS://RPC.ONEHOST.EXAMPLE`.)

This matters more here than it would anywhere else in the repository, because it contradicts the
one thing this module exists to say. Its own docstring: *"the better it is, the more it is still
ONE instrument, and one instrument is zero."* It already refuses a vendor node outright, and
refuses to ship a default node list, precisely so that nobody mistakes one instrument for
several — and then the count it published did exactly that. A verifier that answers
"independently confirmed" on one node's word is the failure mode the module was written to
prevent, and it is reachable by an operator doing nothing worse than pasting a URL twice.

**The fix.** `decide()` now keys the nodes that **voted** (`agree` or `disagree` — the ones that
formed the verdict) by parsed hostname, lowercased, and refuses with a new overall reason
`duplicate_node_in_set` when two of them are the same host. The repeated host is named in a new
`duplicate_hosts_present` field rather than only counted.

Four decisions inside that, each with a law:

- **Hostname, not URL text.** The same basis `excluded_endpoint` already uses, and for the same
  reason: a port and a path are not a second operator, and case and a trailing slash are not
  either. An endpoint with no parseable hostname falls back to its stripped, lowercased text, so
  two identical strings still collide.
- **Identical host only — never a suffix.** `rpc.one.example.org` and `other.one.example.org`
  both vote. The module's existing comment on `excluded_endpoint` makes the argument: guessing at
  operators by suffix "would let an attacker silence a node by naming it".
- **Only nodes that voted.** A host that is merely unreachable twice inflated no count, so
  refusing there would cost a good verdict for nothing.
- **It adds a reason, it hides none.** A duplicate that also dissents reports `nodes_disagree`
  *and* `duplicate_node_in_set`; a repeated vendor node still reports `vendor_node_in_set` and
  not this. `quorum_not_met` is still suppressed by a split, exactly as before.

The module's own law that every reason in the closed table must have a negative control in
`--self-test` is satisfied: `_overall_controls()` gains a `duplicate_node_in_set` fixture, and
`--self-test` reports `overall_reasons_controlled: 5` and passes.

## How to verify it

```
python3 -m unittest discover -s tests   # Ran 1112 tests — OK (skipped=1)   (1099 on main)
python3 e2e_check.py                    # 36/36 checks pass
python3 validate.py --no-write-stats    # OK
python3 independent_confirm.py --self-test   # self_test: pass, 5 overall reasons controlled
python3 verdict.py check / build         # ok: true; rebuild diffs clean
python3 proof_without_execution.py rpc   # rebuild diff clean
```

With `independent_confirm.py` **alone** reverted to `main`, **9 of the 13 new laws fail**:

```
  test_the_same_endpoint_three_times_is_not_a_quorum_of_three
  test_three_spellings_of_one_host_are_not_three_nodes
  test_two_real_nodes_and_one_repeat_still_refuses_at_quorum_two
  test_an_endpoint_with_no_hostname_still_collides_with_itself
  test_the_repeated_host_is_named_not_just_counted
  test_a_split_is_still_reported_as_a_split_as_well
  test_voting_host_reads_the_hostname_not_the_url_text
  test_the_new_reason_is_in_the_closed_table_with_a_control
  test_the_output_holds_exactly_the_documented_keys
```

The other **4 pass on `main` unchanged**, which is the point of them — they are what shows the
refusal costs no good verdict: three distinct hosts are still confirmed with no reasons; a
sibling subdomain still votes; a host unreachable twice is still not a duplicate; a repeated
vendor node is still reported as a vendor node and not as a duplicate.

**Five mutation controls, all killed:**

| mutation | failures |
|---|---|
| duplicates no longer block confirmation | 6 |
| the reason is never emitted | 6 |
| key on the raw URL text instead of the hostname | 5 |
| count every node, not only the ones that voted | 2 |
| match on a suffix, silencing a sibling subdomain | 4 |

## Found, not fixed

- **A caller can still choose three nodes run by one operator on three different hostnames.**
  Hostnames are what a verifier can see; shared operation behind them is not, and inferring it
  would put our judgement back in the trust path — the thing this module refuses to do. The
  module's `notes` already say the verdict is worth what the caller's choices are worth, and
  that remains the honest ceiling. What is fixed here is the case where the tool could see the
  duplication and counted it anyway.
- **`confirm_signature_payment`-style dead code.** None found here; noted only because the
  sibling audit this run did find some.

## What I could not verify

- **No live node, and no XNO moved.** The container has no route to a public Nano RPC, so every
  claim above is from the code and from `decide()`'s pure core, which is deterministic by
  construction and opens no socket. That is also why the finding was provable: the defect is in
  the counting, not in anything a node says.
- **Whether any operator has ever passed a duplicate endpoint.** Not knowable from here. The
  arithmetic was wrong whenever they did.
- **`https://getunstuck.space`** is still not live, as the README says.
