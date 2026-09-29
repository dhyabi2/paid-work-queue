#!/usr/bin/env python3
"""The five gates a USDC-shaped x402 server must pass before it can settle XNO.

A checklist, not a scanner. It cannot read your source, and it does not try:
it asks the five questions `minia2auk` actually measured on their own server,
takes your answers, and prints a verdict you can paste into a pull request.

The point is the order. Four of these gates are a one-line change and the
fifth is not, and a server author who fixes the four cheap ones first has
spent an afternoon and still cannot take a payment:

    "So adding a `nano` branch to `Get()` would not be enough on its own: the
    refund path dies at the unit contract first. Changing that is a decision
    about what the column *means* and about every read site - not a switch
    statement."

So `amount_column_width` is the one that has to be settled, and every other
gate's `next_step` says so.

A checklist that guesses in our favour is worse than no checklist, so an
unanswered gate is never rounded up: all five `true` is the only way to reach
`would_settle`. `null` means "not checked" and produces `unknown`.

Usage:
    python3 server_conformance.py --template > answers.json
    python3 server_conformance.py --answers answers.json [--json]

Exit codes: 0 would_settle, 3 would_refuse, 5 unknown, 4 usage error.

Standard library only and no network; the suite asserts it.
"""

import argparse
import json
import sys

#: The five gates, verbatim in wording and order. `question` is what
#: minia2auk measured; `grep` is the exact thing to go and look at, so the
#: answer is a lookup rather than a recollection; `consequence` is what
#: actually happens when the answer is false, drawn from their own report.
GATES = (
    {
        "id": "network_registered",
        "question": "Does your `Networks` (or equivalent) map contain a `nano:mainnet` entry at all?",
        "grep": "grep -rn 'Networks' -- the map literal that lists base, solana, etc.",
        "consequence": (
            "The network is unknown to the server, so nothing downstream is "
            "ever reached: no scheme lookup, no refunder, no route."
        ),
        "fix": (
            "Add the `nano:mainnet` entry to the network map. One line - but see "
            "amount_column_width before you expect it to settle anything."
        ),
    },
    {
        "id": "settleable_capability",
        "question": "Is the capability bit that gates *advertising* an accept set for nano - not merely map membership?",
        "grep": "grep -rn 'Settleable' -- the capability flag, set only on base today.",
        "consequence": (
            "The network is in the map but never advertised, so a payer is "
            "never offered the nano accept and cannot choose to pay in it. "
            "Map membership alone does not advertise: the capability bit does."
        ),
        "fix": (
            "Set the `Settleable` capability bit for nano, not just the map entry. "
            "One line - but see amount_column_width before you expect it to settle anything."
        ),
    },
    {
        "id": "amount_column_width",
        "question": "Can the column your refunder reads amounts into hold `1000000000000000000000000` raw, or is it a 6-decimal int64?",
        "grep": "grep -rn 'amount_micro' -- the refunds column, and every site that reads it.",
        "consequence": (
            "A nano payment cannot be stored. 1e24 raw (0.000001 XNO) overflows "
            "a 6-decimal int64 column, so refunds strand at status='failed' and "
            "are never broadcast. This is not a switch statement: it is a "
            "decision about what the column means and about every read site."
        ),
        "fix": (
            "Settle what the amount column means before touching the other four gates."
        ),
    },
    {
        "id": "refunder_registered",
        "question": "Does your refunder registry return a non-nil handler for `nano:mainnet`, or does the nil branch mark the row failed?",
        "grep": "grep -rn 'refunder' -- the registry lookup and its nil branch.",
        "consequence": (
            "The nil branch marks the row failed. It sits at status='failed', "
            "attempts=5, tx_hash empty, never broadcast and never retried, with "
            "one log line per attempt that stops after the fifth. Nobody is paged "
            "and the payer is never told."
        ),
        "fix": (
            "Register a refunder for `nano:mainnet` so the registry stops returning nil. "
            "One line - but see amount_column_width before you expect it to settle anything."
        ),
    },
    {
        "id": "chain_route_accepts",
        "question": "Does your chain route answer 200 for nano, or `400 unsupported chain` with a `supported:` list that omits it?",
        "grep": "grep -rn 'unsupported chain' -- the route's allowlist and its error body.",
        "consequence": (
            "The request is refused at the edge with `400 unsupported chain` and "
            "a `supported:` list that omits nano, so a payer never reaches the "
            "settlement path at all."
        ),
        "fix": (
            "Add nano to the chain route's allowlist and its `supported:` list. "
            "One line - but see amount_column_width before you expect it to settle anything."
        ),
    },
)

GATE_IDS = tuple(gate["id"] for gate in GATES)

TEMPLATE_NOTE = (
    "Answer each gate true, false, or leave it null for 'not checked'. An "
    "unchecked gate never counts in our favour: any null and the verdict is "
    "'unknown', never 'would_settle'."
)

EXIT_WOULD_SETTLE = 0
EXIT_WOULD_REFUSE = 3
EXIT_USAGE = 4
EXIT_UNKNOWN = 5


class UsageError(Exception):
    """Something wrong with how the tool was called or with the answers file."""


def template():
    """The answers file to fill in: five gates, in order, every answer null."""
    return {
        "_note": TEMPLATE_NOTE,
        "gates": [
            {
                "id": gate["id"],
                "question": gate["question"],
                "look_at": gate["grep"],
                "answer": None,
            }
            for gate in GATES
        ],
    }


def parse_answers(document):
    """Read answers from the template shape, or from a flat {id: bool} mapping.

    The flat shape is accepted because a server author who has already read
    the five questions will write one by hand, and refusing it would send them
    back for a template they do not need.
    """
    if not isinstance(document, dict):
        raise UsageError("the answers file must contain a JSON object")

    if "gates" in document:
        gates = document["gates"]
        if not isinstance(gates, list):
            raise UsageError("'gates' must be a list")
        answers, seen = {}, []
        for index, entry in enumerate(gates):
            if not isinstance(entry, dict):
                raise UsageError("gates[%d] is not an object" % index)
            gate_id = entry.get("id")
            if gate_id not in GATE_IDS:
                raise UsageError(
                    "gates[%d] has id %r; the five ids are %s"
                    % (index, gate_id, ", ".join(GATE_IDS))
                )
            if gate_id in answers:
                raise UsageError("gate %r is answered more than once" % gate_id)
            answers[gate_id] = _answer_value(gate_id, entry.get("answer"))
            seen.append(gate_id)
        missing = [g for g in GATE_IDS if g not in answers]
        if missing:
            raise UsageError(
                "the answers file is missing gate(s): %s. Start from "
                "--template." % ", ".join(missing)
            )
        return answers

    answers = {}
    for gate_id in GATE_IDS:
        if gate_id not in document:
            raise UsageError(
                "the answers file is missing gate(s): %s. Start from --template."
                % ", ".join(g for g in GATE_IDS if g not in document)
            )
        answers[gate_id] = _answer_value(gate_id, document[gate_id])
    return answers


def _answer_value(gate_id, value):
    """true, false or null. A string 'true' is a usage error, not a guess."""
    if value is None or isinstance(value, bool):
        return value
    raise UsageError(
        "gate %r has answer %r; it must be true, false, or null for "
        "'not checked'" % (gate_id, value)
    )


def evaluate(answers):
    """The verdict. `would_settle` requires all five true; any null blocks it."""
    blocking = [g["id"] for g in GATES if answers.get(g["id"]) is False]
    unknown = [g["id"] for g in GATES if answers.get(g["id"]) is None]

    if blocking:
        verdict = "would_refuse"
    elif unknown:
        verdict = "unknown"
    else:
        verdict = "would_settle"

    return {
        "verdict": verdict,
        "gates": [
            {
                "id": gate["id"],
                "question": gate["question"],
                "answer": answers.get(gate["id"]),
                "consequence": gate["consequence"],
            }
            for gate in GATES
        ],
        "blocking": blocking,
        "unknown": unknown,
        "next_step": _next_step(verdict, blocking, unknown),
    }


def _next_step(verdict, blocking, unknown):
    if verdict == "would_settle":
        return (
            "All five gates pass. A nano:mainnet payment can be advertised, "
            "accepted, stored and refunded on this server."
        )
    if verdict == "unknown":
        return (
            "Nothing is known to be broken, but %s %s not been checked, so this "
            "is not a pass. Answer %s and run it again."
            % (
                ", ".join(unknown),
                "has" if len(unknown) == 1 else "have",
                "it" if len(unknown) == 1 else "them",
            )
        )

    if "amount_column_width" in blocking:
        return (
            "Start with amount_column_width, because the other gates cannot "
            "help until it is settled. The quantum is 1 micro = 10**24 raw = "
            "0.000001 XNO, and the largest amount a 6-decimal int64 can hold "
            "is 9223372036854775807 micro. `usdc_shape.py` in this repository "
            "is that mapping in both directions, with an explicit refusal "
            "instead of a silent truncation, plus vectors in "
            "`vectors/usdc-shape-v1.json` for porting it to another language."
        )
    fixes = [g["fix"] for g in GATES if g["id"] in blocking]
    return (
        "%s Note that amount_column_width is answered true here, so the "
        "amount column is not in the way - but if that answer changes, settle "
        "it first, because it is not a switch statement."
        % " ".join(fixes)
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--template", action="store_true",
                        help="write a blank answers file to stdout")
    parser.add_argument("--answers", help="path to a filled-in answers file")
    parser.add_argument("--json", action="store_true",
                        help="print the verdict as JSON")
    args = parser.parse_args(argv)

    if args.template:
        if args.answers:
            print("--template and --answers are mutually exclusive", file=sys.stderr)
            return EXIT_USAGE
        json.dump(template(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return EXIT_WOULD_SETTLE

    if not args.answers:
        print("nothing to do: pass --answers FILE, or --template to make one",
              file=sys.stderr)
        return EXIT_USAGE

    try:
        with open(args.answers, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        print("cannot read %s (%s)" % (args.answers, exc), file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print("%s is not valid JSON (%s)" % (args.answers, exc), file=sys.stderr)
        return EXIT_USAGE

    try:
        answers = parse_answers(document)
    except UsageError as exc:
        print("%s" % exc, file=sys.stderr)
        return EXIT_USAGE

    result = evaluate(answers)
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(result)

    return {
        "would_settle": EXIT_WOULD_SETTLE,
        "would_refuse": EXIT_WOULD_REFUSE,
        "unknown": EXIT_UNKNOWN,
    }[result["verdict"]]


def _print_human(result):
    mark = {True: "pass", False: "FAIL", None: "?   "}
    print("verdict: %s\n" % result["verdict"])
    for gate in result["gates"]:
        print("  [%s] %s" % (mark[gate["answer"]], gate["id"]))
        if gate["answer"] is not True:
            print("         %s" % gate["consequence"])
    print("\nnext step: %s" % result["next_step"])


if __name__ == "__main__":
    sys.exit(main())
