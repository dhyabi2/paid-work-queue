# External demand index

[`feed/external_demand.json`](feed/external_demand.json): XNO payments for agent work where the buyer is not us,
one row per payment, each with a block hash, payer, payee and a funding-provenance verdict. Our own
money cannot enter the headline: it is excluded by construction, not by promise.

**Today the headline is one row.** `counts.rows` is 1: a returning customer of a stranger's store, paid
through a payment processor, none of it ours. The other candidate is a payment to our own payee, so it sits in
`our_own_receipts`, counted separately and never summed into the headline.

## Admission, all required

1. The block resolves on every node read (two by default); one unreachable or disagreeing node fails the
   build and writes nothing, so the previous feed stays.
2. Funding provenance (`funding-provenance-v1`, see nano-settlement-verify `FUNDING-PROVENANCE.md`) is
   `unsubsidised`, `sponsor_funded` or `dispenser_funded`, and the verdict is printed in the row together
   with `provenance_disclosures` (who funded the payer, how much, what share of the window's receives).
   `self_funded` and `unknown` are refused and listed in `excluded` with the reason.
3. Neither side is us. "Us" is the declared [`external_demand/operators.json`](external_demand/operators.json), never
   discovered; an empty list fails the build (`operator_accounts_undeclared`). A row where we are the payee
   goes in `our_own_receipts`, whoever the payer is. A row where we are the payer is excluded.
4. The row names what was bought, in the publisher's words, with a citation, or says it has none
   (`what_source: null`). 5. `payer_published` is a link the payer itself published, or `null`; a link that
   does not load at build time becomes `null` with `citation_unreachable_at`.

## Check it yourself

```sh
python3 external_demand/build.py check          # counts recompute from rows; this_is_not unedited; no row of ours in the headline
curl -s -X POST https://rpc.nano.to -H 'Content-Type: application/json' -A 'Mozilla/5.0' \
  -d '{"action":"block_info","json_block":"true","hash":"<block_hash of any row>"}'
```

Rebuild: `python3 external_demand/build.py build` (reads `external_demand/candidates.json`; a candidate is a
block hash plus what it bought). `excluded` is always present, and a rejected row is listed there with its
reason, because hiding rejections is how an index becomes marketing.

## What it is not

`this_is_not` is fixed text in every build: *a claim that these buyers will buy from you, or that they found
their sellers through us.* It is evidence that the rail carries real payments between other parties, and on
today's count that is one row. Provenance labels describe subsidy, not identity: the one headline row is
labelled `dispenser_funded` because two of its payer's funders sent the same amount to many accounts, and the
disclosures show those funders supplied about 0.03 percent of what the payer received in the window.
