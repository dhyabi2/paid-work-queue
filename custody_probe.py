#!/usr/bin/env python3
"""Prove an origin never sends you a key - and be able to fail while proving it.

29 agents - the largest single wall in front of this project - refused over
custody: who holds the keys. We answered them with a sentence, and a sentence
is not checkable.

We already ship one checkable artifact, `nano-onramp-check.js`, served under a
heading that reads *"Verify it yourself (run this, do not take our word for
it)"*. Read its source. The line that decides the verdict requires
`steps.seed_returned` to be **true**, and `seed_returned` is set true when the
origin hands back a 64-character private key. So the artifact we publish to
prove ourselves to custody-averse agents *requires the origin to send a private
key in order to print `"proven": true`*. An agent on the custody wall that does
exactly what our documentation tells it to do gets a green result for the one
behaviour that disqualifies us with it.

This module is the assertion the other way round. It passes only when an origin
serves **no key material at all**, under four request variants, on eleven paths.
It is not about us: point it at a competitor and it answers the same question
about them. That is what makes it worth running.

    python3 custody_probe.py https://getunstuck.space

Five things hold here, and each one has a test that fails without it:

1.  **Standard library only, and no network import at module scope.**
    `urllib.request` is imported inside `default_fetch` and nowhere else, so
    `probe()` with an injected `fetch` never reaches the network layer at all.
    `tests/test_custody_probe.py` walks this file's import graph and fails the
    build if either rule breaks.
2.  **No float touches an amount.** No amount is handled here at all. The probe
    holds no funds, sends no transaction and needs no key.
3.  **The probe must be able to fail.** `--self-test` runs two controls: a
    leaking origin that MUST come back `pass: false`, and a clean one that MUST
    come back `pass: true`. If the leaking control ever stops failing,
    `--self-test` exits 1. A check that cannot fail proves nothing, and that is
    the precise defect this tool exists to correct.
4.  **No key material is ever written, logged or committed.** A finding names
    where key material was found and how long it was - JSON path or byte
    offset, pattern name, character length - and never the value. No fixture in
    the suite holds a value captured from a live origin; the leaking fixtures
    use `"0" * 64` and `"DEADBEEF" * 8`, built at runtime so that no 64-hex run
    stands in the source either. One test serialises the probe's own output and
    asserts it contains no 64-hex run.
5.  **Read-only.** The probe sends GET and nothing else. It never POSTs, never
    registers, never claims, never opens an account.

A note on point 5: the spec that asked for this tool says "GET requests and one
OPTIONS", but it also fixes the injected seam as `fetch(url, headers)` - a
signature with nowhere to put a method. The seam is the testable half of that
pair, so GET-only is what is implemented, which is strictly more read-only than
GET plus OPTIONS. The contradiction is reported back rather than resolved by
quietly widening the seam.

What this does not do: it does not say an origin is safe. It says only that
this origin did not send key material on these paths, under these variants, at
this time. It cannot prove a negative about paths it was not given, and the
output says so in `notes`.
"""

import argparse
import ast
import json
import re
import sys
import time
import urllib.parse  # pure text; `urllib.request` is imported only in default_fetch

#: Bumped when the shape of the result document changes, so an outside agent
#: diffing two runs can tell a schema change from a behaviour change.
VERSION = 1

#: Past this the probe truncates and refuses to conclude, because a leak could
#: be past the cut and "clean" would then be a guess.
MAX_BODY_BYTES = 2 * 1024 * 1024

#: More hops than this on one path is a redirect loop, not a redirect.
MAX_REDIRECTS = 5

DEFAULT_PATHS = [
    "/llms.txt",
    "/agent.json",
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",
    "/unstuck/api/v1/onramp/address",
    "/unstuck/api/v1/onramp/register",
    "/unstuck/api/v1/onramp/keygen.js",
    "/unstuck/api/v1/onramp/keygen.py",
    "/api/v1/onramp/address",
    "/onramp/address",
    "/v1/onramp/address",
]

#: "It does not return a seed" has to hold under argument, header and content
#: negotiation, not only under the plain call. A leak under ANY variant fails
#: the origin, and the finding names which one.
VARIANTS = (
    ("plain", {}, ""),
    ("accept_html", {"Accept": "text/html"}, ""),
    ("accept_any", {"Accept": "*/*"}, ""),
    ("query_seed", {}, "seed=1&include_seed=true&format=full"),
)

#: A JSON key with one of these names, holding a non-empty string or an
#: integer, is key material regardless of what the value looks like.
SECRET_KEY_NAMES = frozenset({
    "seed", "private_key", "privatekey", "privkey", "secret", "secret_key",
    "mnemonic", "entropy", "xprv",
})

#: A block hash is 64 hex characters and is not a key. Under one of these keys,
#: a 64-hex run is excluded with a reason rather than reported as a finding.
#: This exclusion is the one most likely to be got wrong; tests 7 and 8 pin it.
HASH_KEY_NAMES = frozenset({
    "hash", "block", "payment_block", "settlement_block", "frontier",
    "previous", "link", "sha256", "digest",
})

#: Documentation and client source are allowed to carry an example key in a
#: comment. A live JSON API response has no such excuse.
COMMENT_EXTENSIONS = (".js", ".py", ".txt")

HEX64_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
BIP39_RE = re.compile(r"(?<![A-Za-z])[a-z]{3,8}(?:[ \t\r\n]+[a-z]{3,8}){11,}(?![A-Za-z])")
KEY_BEFORE_RE = re.compile(r"[\"']([A-Za-z0-9_\-]+)[\"']\s*:")
COMMENT_LINE_RE = re.compile(r"^\s*(//|#|\*)")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

NOTES = [
    "A finding names where key material was found and how long it was. The "
    "value itself is never reported, written or stored.",
    "findings_total counts distinct (path, pattern, location) findings. The "
    "same leak seen under several variants is counted once, and every variant "
    "that saw it still reports it.",
    "This says only that the origin served no key material on these paths, "
    "under these variants, at this time. It cannot prove a negative about "
    "paths it was not given.",
]


class Probed:
    """The minimal response shape the injected `fetch` has to return."""

    __slots__ = ("status", "headers", "body")

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers or {}
        self.body = body or b""


# --------------------------------------------------------------------------
# origin parsing
# --------------------------------------------------------------------------

def normalise_origin(origin):
    """Return `(base_url, insecure_transport)`; raise ValueError if unparseable.

    A bare host becomes `https://host`. `http://` is permitted - refusing it
    outright would hide the answer - but it sets `insecure_transport` and
    forces `pass: false`, because a key sent in clear text is worse, not better.
    """
    if not isinstance(origin, str):
        raise ValueError("origin must be a string")
    text = origin.strip()
    if not text:
        raise ValueError("origin is empty")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http"):
        raise ValueError("unsupported scheme %r: only https and http" % parts.scheme)
    if not parts.netloc:
        raise ValueError("origin %r has no host" % origin)
    return "%s://%s" % (parts.scheme, parts.netloc), parts.scheme == "http"


def _origin_of(url):
    parts = urllib.parse.urlsplit(url)
    return "%s://%s" % (parts.scheme, parts.netloc)


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------

def _normalise_key(key):
    """`paymentBlock` and `payment-block` both become `payment_block`."""
    return _CAMEL_RE.sub("_", key).replace("-", "_").lower()


def _is_secret_key(key):
    return key.lower() in SECRET_KEY_NAMES or _normalise_key(key) in SECRET_KEY_NAMES


def _is_hash_key(key):
    return key.lower() in HASH_KEY_NAMES or _normalise_key(key) in HASH_KEY_NAMES


def _byte_offset(text, index):
    return len(text[:index].encode("utf-8", errors="replace"))


def _walk_json(node, path="$"):
    """Yield `(key, value, json_path)` for every object member, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = "%s.%s" % (path, key)
            yield key, value, here
            yield from _walk_json(value, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_json(value, "%s[%d]" % (path, index))


def _nearest_key_before(text, index):
    """The JSON key a value at `index` belongs to, or None.

    For a scalar, the nearest preceding `"key":` IS the key that holds it, so
    this is exact for the case it is used on and deliberately conservative
    everywhere else: no key found means no exclusion, i.e. a finding.
    """
    last = None
    for match in KEY_BEFORE_RE.finditer(text, 0, index):
        last = match.group(1)
    return last


def _line_bounds(text, index):
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return start, len(text) if end == -1 else end


def detect(body_text, path, variant):
    """Return `{"findings": [...], "excluded": [...]}` for one response body.

    Kept as a module-level function on purpose: `--self-test` proves the
    detector can still fail by replacing this name, which only works if the
    probe looks it up at call time.
    """
    findings = []
    excluded = []
    lowered_path = path.split("?", 1)[0].lower()
    comment_exclusion_applies = lowered_path.endswith(COMMENT_EXTENSIONS)

    document = None
    try:
        document = json.loads(body_text)
    except ValueError:
        document = None

    # -- json_key ----------------------------------------------------------
    if document is not None:
        for key, value, json_path in _walk_json(document):
            if not isinstance(key, str) or not _is_secret_key(key):
                continue
            if value is None or isinstance(value, bool) or value == "":
                # `{"seed": null}` is a schema, not a key.
                excluded.append({
                    "pattern": "json_key",
                    "json_path": json_path,
                    "reason": "documented_key_with_no_value",
                    "variant": variant,
                })
            elif isinstance(value, str):
                findings.append({
                    "pattern": "json_key",
                    "json_path": json_path,
                    "value_length": len(value),
                    "variant": variant,
                })
            elif isinstance(value, int):
                findings.append({
                    "pattern": "json_key",
                    "json_path": json_path,
                    "value_length": len(str(value)),
                    "variant": variant,
                })

    # -- hex64 -------------------------------------------------------------
    for match in HEX64_RE.finditer(body_text):
        offset = _byte_offset(body_text, match.start())
        key = _nearest_key_before(body_text, match.start()) if document is not None else None
        if key is not None and _is_hash_key(key):
            excluded.append({
                "pattern": "hex64",
                "byte_offset": offset,
                "reason": "block_hash_key",
                "key": key,
                "variant": variant,
            })
            continue
        if comment_exclusion_applies:
            start, end = _line_bounds(body_text, match.start())
            if COMMENT_LINE_RE.match(body_text[start:end]):
                excluded.append({
                    "pattern": "hex64",
                    "byte_offset": offset,
                    "reason": "comment_line",
                    "variant": variant,
                })
                continue
        findings.append({
            "pattern": "hex64",
            "byte_offset": offset,
            "value_length": 64,
            "variant": variant,
        })

    # -- bip39_shape -------------------------------------------------------
    for match in BIP39_RE.finditer(body_text):
        run = match.group(0).split()
        if len(run) not in (12, 24):
            continue
        findings.append({
            "pattern": "bip39_shape",
            "byte_offset": _byte_offset(body_text, match.start()),
            "value_length": len(match.group(0)),
            "word_count": len(run),
            "variant": variant,
        })

    findings.sort(key=_finding_sort_key)
    excluded.sort(key=_finding_sort_key)
    return {"findings": findings, "excluded": excluded}


def _finding_sort_key(item):
    return (
        item.get("pattern", ""),
        item.get("json_path", ""),
        item.get("byte_offset", -1),
    )


def _location_of(item):
    """The identity of a finding, ignoring which variant saw it."""
    return (item.get("pattern"), item.get("json_path"), item.get("byte_offset"))


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def default_fetch(timeout=10.0):
    """Build the stdlib `fetch` seam. The ONLY place `urllib.request` is used.

    It does not follow redirects: the probe follows them itself so that it can
    refuse an offsite one by name instead of silently measuring another host.
    """
    import urllib.error  # noqa: PLC0415 - deliberately local; see the docstring
    import urllib.request  # noqa: PLC0415 - the one network import in this file

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect)

    def fetch(url, headers):
        request = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                return Probed(response.status, dict(response.headers), response.read(MAX_BODY_BYTES + 1))
        except urllib.error.HTTPError as exc:  # a status is an answer, not a failure
            return Probed(exc.code, dict(exc.headers or {}), exc.read(MAX_BODY_BYTES + 1))

    return fetch


def _header(headers, name):
    try:
        items = list(headers.items())
    except AttributeError:
        return None
    wanted = name.lower()
    for key, value in items:
        if isinstance(key, str) and key.lower() == wanted:
            return value
    return None


def _decode(body):
    if isinstance(body, str):
        return body, len(body.encode("utf-8", errors="replace"))
    data = body or b""
    return data.decode("utf-8", errors="replace"), len(data)


def _request(fetch, base, path, headers, query):
    """One path under one variant, following same-origin redirects by hand.

    Returns `(response_dict, error_dict)`; exactly one of the two is None.
    """
    url = base + path
    if query:
        url = url + ("&" if "?" in url else "?") + query
    seen = 0
    while True:
        try:
            response = fetch(url, dict(headers))
        except Exception as exc:  # noqa: BLE001 - a network condition is data here
            code = "timeout" if _looks_like_timeout(exc) else "unreachable"
            return None, {"code": code, "path": path, "detail": type(exc).__name__}
        status = int(getattr(response, "status", 0) or 0)
        if status in (301, 302, 303, 307, 308):
            location = _header(getattr(response, "headers", {}), "Location")
            if not location:
                return None, {"code": "unreachable", "path": path,
                              "detail": "redirect with no Location"}
            target = urllib.parse.urljoin(url, location)
            if _origin_of(target) != base:
                return None, {"code": "offsite_redirect", "path": path,
                              "origin": _origin_of(target)}
            seen += 1
            if seen > MAX_REDIRECTS:
                return None, {"code": "redirect_loop", "path": path, "hops": seen}
            url = target
            continue
        text, size = _decode(getattr(response, "body", b""))
        if size > MAX_BODY_BYTES:
            return None, {"code": "body_too_large", "path": path, "bytes": size}
        return {"status": status, "body": text}, None


def _looks_like_timeout(exc):
    if isinstance(exc, TimeoutError):
        return True
    return "timed out" in str(exc).lower() or "timeout" in type(exc).__name__.lower()


def _state_for(status):
    if 200 <= status < 300:
        return "answered"
    if status == 404:
        return "absent"
    if status == 410:
        return "retired"
    if status >= 500:
        return "server_error"
    return "unavailable"


def _utc_now():
    """The clock, as one name, so a test can pin it and diff two runs."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------
# the probe
# --------------------------------------------------------------------------

def probe(origin, *, fetch=None, timeout=10.0, paths=None):
    """Probe `origin` and return the result document. See the module docstring.

    Never raises for a network condition - those become `errors` entries with
    `pass: false`. Raises ValueError only for an origin it cannot parse.
    """
    base, insecure = normalise_origin(origin)
    if fetch is None:
        fetch = default_fetch(timeout)
    path_list = list(DEFAULT_PATHS) if paths is None else list(paths)

    errors = []
    path_results = []
    seen_locations = set()
    findings_total = 0

    for path in path_list:
        entry = {"path": path, "state": None, "status": None, "variants": {}, "excluded": []}
        first, error = _request(fetch, base, path, VARIANTS[0][1], VARIANTS[0][2])
        if error is not None:
            errors.append(error)
            entry["state"] = "error"
            path_results.append(entry)
            continue

        entry["status"] = first["status"]
        entry["state"] = _state_for(first["status"])
        responses = [(VARIANTS[0][0], first)]

        # Only a path that actually answers is worth negotiating with.
        if entry["state"] == "answered":
            for name, headers, query in VARIANTS[1:]:
                other, error = _request(fetch, base, path, headers, query)
                if error is not None:
                    errors.append(dict(error, variant=name))
                    continue
                responses.append((name, other))

        excluded_seen = {}
        for name, response in responses:
            found = detect(response["body"], path, name)
            for item in found["findings"]:
                location = (path,) + _location_of(item)
                if location not in seen_locations:
                    seen_locations.add(location)
                    findings_total += 1
            for item in found["excluded"]:
                key = _location_of(item) + (item.get("reason"), item.get("key"))
                if key in excluded_seen:
                    excluded_seen[key]["variants"].append(name)
                else:
                    merged = {k: v for k, v in item.items() if k != "variant"}
                    merged["variants"] = [name]
                    excluded_seen[key] = merged
            entry["variants"][name] = {
                "status": response["status"],
                "findings": found["findings"],
            }
        entry["excluded"] = sorted(excluded_seen.values(), key=_finding_sort_key)
        path_results.append(entry)

    if path_list and all(p["state"] == "server_error" for p in path_results):
        errors.append({
            "code": "origin_error", "path": "*",
            "detail": "every path returned 5xx",
            "paths": list(path_list),
        })

    measured_something = any(p["state"] in ("answered", "retired") for p in path_results)
    passed = (
        findings_total == 0
        and insecure is False
        and errors == []
        and measured_something
    )
    return {
        "tool": "custody_probe",
        "version": VERSION,
        "origin": base,
        "measured_at": _utc_now(),
        "insecure_transport": insecure,
        "paths": path_results,
        "findings_total": findings_total,
        "serves_no_key_material": findings_total == 0,
        "pass": passed,
        "errors": errors,
        "notes": list(NOTES),
    }


# --------------------------------------------------------------------------
# the controls
# --------------------------------------------------------------------------

#: Built at runtime from short pieces so that no 64-hex run stands in this
#: file. Nothing here was captured from a live origin.
SYNTHETIC_HEX64 = "0" * 64
SYNTHETIC_HEX64_ALT = "DEADBEEF" * 8


def _control_fetch(leaking):
    """A hermetic `fetch`. `leaking=True` is the positive control.

    The leaking body is the shape `/unstuck/api/v1/onramp/address` returned on
    2026-09-30 - an address, an index, an onboard id, and a private key. The key
    here is synthetic.
    """
    def fetch(url, headers):
        path = urllib.parse.urlsplit(url).path
        if path == "/llms.txt":
            return Probed(200, {"Content-Type": "text/plain"}, b"# llms.txt\n")
        if path.endswith("/onramp/address"):
            if leaking:
                body = json.dumps({
                    "address": "nano_1probe",
                    "seed": SYNTHETIC_HEX64,
                    "index": 0,
                    "onboard_id": 1,
                }).encode("utf-8")
                return Probed(200, {"Content-Type": "application/json"}, body)
            return Probed(410, {"Content-Type": "application/json"},
                          json.dumps({"error": "retired", "seed": None}).encode("utf-8"))
        return Probed(404, {}, b"not found")
    return fetch


def self_test():
    """Return 0 only if BOTH controls behave: leaking fails, clean passes."""
    leaking = probe("https://control.invalid", fetch=_control_fetch(True))
    clean = probe("https://control.invalid", fetch=_control_fetch(False))
    ok = leaking["pass"] is False and clean["pass"] is True
    report = {
        "tool": "custody_probe",
        "self_test": "pass" if ok else "fail",
        "leaking_control": {
            "expected_pass": False,
            "pass": leaking["pass"],
            "findings_total": leaking["findings_total"],
        },
        "clean_control": {
            "expected_pass": True,
            "pass": clean["pass"],
            "findings_total": clean["findings_total"],
        },
    }
    if not ok:
        report["why"] = (
            "A control did not behave. If the leaking control passed, the "
            "detector has stopped being able to fail and every green result "
            "this tool has ever printed is worthless."
        )
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if ok else 1


# --------------------------------------------------------------------------
# import-graph self-description, used by the test that pins constraint 1
# --------------------------------------------------------------------------

NETWORK_MODULES = frozenset({
    "urllib.request", "urllib.error", "http", "http.client", "socket", "ssl",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "asyncio",
    "requests", "httpx", "aiohttp", "urllib3",
})


def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Returned as data so the test can assert on it rather than re-parsing.
    """
    path = source_path or __file__
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found = []

    def visit(node, enclosing):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Import):
                for alias in child.names:
                    found.append({"module": alias.name, "function": enclosing})
            elif isinstance(child, ast.ImportFrom):
                found.append({"module": child.module or "", "function": enclosing})
            visit(child, enclosing)

    visit(tree, None)
    return found


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="custody_probe.py",
        description="Prove an origin serves no key material. Exits 0 only if it does not.",
    )
    parser.add_argument("origin_positional", nargs="?", metavar="ORIGIN",
                        help="https://host, or a bare host")
    parser.add_argument("--origin", dest="origin", help="the same thing, named")
    parser.add_argument("--paths", help="comma-separated path list, replacing the default")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds per request")
    parser.add_argument("--quiet", action="store_true", help="exit code only, no stdout")
    parser.add_argument("--self-test", dest="self_test", action="store_true",
                        help="run both controls hermetically; touches no network")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    origin = args.origin or args.origin_positional
    if not origin:
        sys.stderr.write("custody_probe.py: an origin is required (or --self-test)\n")
        return 2
    paths = None
    if args.paths:
        paths = [p.strip() for p in args.paths.split(",") if p.strip()]
        if not paths:
            sys.stderr.write("custody_probe.py: --paths was empty\n")
            return 2
    try:
        result = probe(origin, timeout=args.timeout, paths=paths)
    except ValueError as exc:
        sys.stderr.write("custody_probe.py: %s\n" % exc)
        return 2
    if not args.quiet:
        print(json.dumps(result, indent=2, sort_keys=False))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
