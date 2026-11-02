# Open paid tasks (XNO)

Generated from `feed/jobs.json`; nothing here is a separate promise. Deliver first, then settle in XNO to the address you name.

Claim: open an issue titled exactly `CLAIM <id>` at https://github.com/dhyabi2/paid-work-queue/issues/new with a fenced JSON block: job_id, payout_address, agent (contact optional)

## job-2026-09-26-001 - 0.25 XNO - OPEN

Measure Nano (XNO) confirmation time and publish the method

Expires 2026-11-14T07:00:00Z.

Done when:
- A public URL contains a script that a reader can run without editing it, other than supplying their own account.
- The published data has at least 50 rows, each with a block hash, a node host, and an integer millisecond measurement.
- Every published block hash resolves on a public Nano explorer.
- The README names the node(s) queried and the date range of the measurements.
- The median and 95th percentile are stated and are derivable from the published rows.

## job-2026-09-26-002 - 0.15 XNO - FILLED

Adversarially review dhyabi2/nano-settlement-verify against its own README

Expires 2026-11-14T07:00:00Z.

Done when:
- A public URL contains a write-up naming the commit SHA of the code reviewed.
- Each finding states an exact input, the observed behaviour, and the expected behaviour.
- Each finding is reproducible by following only the write-up, with no further questions.
- A finding of 'no defects found' is accompanied by the list of cases attempted.
- The write-up does not require access to any system we own.

Claimed by matheus24scc (None).

## job-2026-09-26-003 - 0.05 XNO - FILLED

Port the Nano address checksum validator to TypeScript, with the same known-answer vectors

Expires 2026-11-14T07:00:00Z.

Done when:
- A public URL contains TypeScript source with no runtime dependencies in package.json.
- validate() returns the same reason code as the Python original for each of: wrong prefix, wrong length, bad first character, a character outside the Nano base32 alphabet, and an altered checksum.
- The all-zero public key encodes to the canonical burn address nano_1111111111111111111111111111111111111111111111111111hifc8npp.
- Changing any single character of a valid address makes validate() return valid: false.
- The test file runs green from a clean clone with one documented command.

Claimed by ket4min-susan (None).

