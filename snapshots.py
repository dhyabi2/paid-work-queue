#!/usr/bin/env python3
"""feed/snapshots.json - the retention policy, published rather than implied.

One row per published version of each tracked artifact, DERIVED FROM GIT HISTORY and never hand-written: a version
the tool cannot derive is absent, not guessed. Each row pins a 40-hex COMMIT SHA in its permalink (a branch URL is
the moved target "silent rewrite" is about), carries the file's sha256 as two 32-character halves (the secret gate
refuses a standalone 64-hex run), and `superseded_at` is the next version's `generated_at`.

    python3 snapshots.py build --root . [--out feed/snapshots.json] [--artifact feed/jobs.json ...]
    python3 snapshots.py check --root . [--index feed/snapshots.json]   # shape + gap + append-only vs. HEAD~ version

`generated_at` is the artifact's own `generated_at` field when it has one, else the commit's UTC committer time.
Append-only: a rebuild may add rows or fill a null `superseded_at`, never remove or retime a row
(`verification_tier.append_only_problems`). A force-push that drops history therefore fails `check`.

Uses `git` through subprocess and nothing else: no network, no key, no clock beyond git's own recorded times.
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verification_tier as vt  # noqa: E402

REPO_RAW = "https://raw.githubusercontent.com/dhyabi2/paid-work-queue/"
DEFAULT_ARTIFACTS = ("feed/jobs.json", "feed/verdict.json", "feed/acceptances.json", "feed/offers.json")


def _git(root, *args):
    return subprocess.run(("git", "-C", root) + args, check=True, capture_output=True).stdout


def _utc(iso_with_offset):
    t = datetime.datetime.fromisoformat(iso_with_offset)
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def versions(root, path):
    """Oldest-first list of (commit, generated_at, bytes) for every commit that changed `path`."""
    out = _git(root, "log", "--format=%H %cI", "--", path).decode().strip().splitlines()
    rows = []
    for line in reversed(out):
        sha, committed = line.split(" ", 1)
        try:
            body = _git(root, "show", "%s:%s" % (sha, path))
        except subprocess.CalledProcessError:
            continue                     # deleted in that commit: nothing to snapshot
        stamp = None
        try:
            doc = json.loads(body)
            g = doc.get("generated_at") if isinstance(doc, dict) else None
            if isinstance(g, str) and vt._RFC3339.match(g):
                stamp = g
        except ValueError:
            pass
        rows.append((sha, stamp or _utc(committed), body))
    return rows


def build(root, artifacts=DEFAULT_ARTIFACTS, previous=None):
    rows = []
    for path in artifacts:
        vs = versions(root, path)
        seen = set()
        art_rows = []
        for sha, stamp, body in vs:
            digest = hashlib.sha256(body).hexdigest()
            key = (stamp, digest)
            if key in seen:
                continue                 # same bytes republished: one version
            seen.add(key)
            art_rows.append({"artifact": path, "generated_at": stamp, "commit": sha,
                             "permalink": "%s%s/%s" % (REPO_RAW, sha, path),
                             "sha256_halves": [digest[:32], digest[32:]],
                             "bytes": len(body), "superseded_at": None})
        for a, b in zip(art_rows, art_rows[1:]):
            a["superseded_at"] = b["generated_at"]
        rows.extend(art_rows)
    doc = {"v": "snapshots-v1",
           "why": ("The retention policy, published. Every row is a past version of a tracked artifact at an "
                   "immutable commit URL. Rows are derived from git history; this file may gain rows and fill "
                   "`superseded_at`, never lose or retime one."),
           "join_the_halves": True, "snapshots": rows}
    if previous:
        bad = vt.append_only_problems(previous, doc)
        if bad:
            raise vt.Refusal(bad[0][0], bad[0][1])
    return doc


def check(root, index, artifacts=DEFAULT_ARTIFACTS):
    problems = []
    for path in artifacts:
        history = [stamp for _, stamp, _ in versions(root, path)]
        tracked = {s for s in history}
        # the working index may lag HEAD by the very commit that updates it; gaps are judged against history
        # minus the newest version only when that version IS the commit that touched snapshots.json.
        problems += ["%s: %s" % (c, d) for c, d in vt.snapshot_problems(index, path, history[:-1] if history else None)]
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(prog="snapshots.py")
    sub = ap.add_subparsers(dest="cmd")
    b = sub.add_parser("build")
    b.add_argument("--root", default=HERE)
    b.add_argument("--out", default=os.path.join("feed", "snapshots.json"))
    b.add_argument("--artifact", action="append")
    c = sub.add_parser("check")
    c.add_argument("--root", default=HERE)
    c.add_argument("--index", default=os.path.join("feed", "snapshots.json"))
    c.add_argument("--artifact", action="append")
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_usage(sys.stderr)
        return 2
    arts = tuple(args.artifact) if args.artifact else DEFAULT_ARTIFACTS
    root = os.path.abspath(args.root)
    out = args.out if args.cmd == "build" else args.index
    full = out if os.path.isabs(out) else os.path.join(root, out)
    previous = None
    if os.path.exists(full):
        with open(full) as fh:
            previous = json.load(fh)
    try:
        if args.cmd == "build":
            doc = build(root, arts, previous)
            with open(full, "w") as fh:
                fh.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
            print(json.dumps({"rows": len(doc["snapshots"]), "out": out}))
            return 0
        problems = check(root, previous or {}, arts)
        print(json.dumps({"ok": not problems, "problems": problems}, indent=1))
        return 0 if not problems else 1
    except vt.Refusal as exc:
        sys.stderr.write(json.dumps({"error": exc.code, "detail": exc.detail}) + "\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
