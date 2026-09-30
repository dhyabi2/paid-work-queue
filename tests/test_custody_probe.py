"""The probe that proves an origin serves no key material - and can still fail.

Every test here injects its own `fetch`. Nothing in this file opens a socket,
reads `jobs.json`, or depends on a live origin, so a failure here is a defect
in the probe and never a network condition.

No 64-hex run stands in this file either. The leaking fixtures build their key
material at runtime from `"0" * 64` and `"DEADBEEF" * 8`, which is both the
project's secret gate and constraint 4 of the spec: a value captured from a
live origin must never reach a fixture.
"""

import ast
import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import custody_probe  # noqa: E402
from custody_probe import (  # noqa: E402
    DEFAULT_PATHS, MAX_BODY_BYTES, NETWORK_MODULES, Probed, import_graph,
    main, normalise_origin, probe,
)

SEED = "0" * 64                 # synthetic, never captured
ALT_SEED = "DEADBEEF" * 8       # synthetic, never captured
ONRAMP = "/unstuck/api/v1/onramp/address"
KEYGEN = "/unstuck/api/v1/onramp/keygen.js"


def body(payload):
    if isinstance(payload, (dict, list)):
        return json.dumps(payload).encode("utf-8")
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return payload


def responder(table, default=(404, b"not found"), record=None):
    """Build a `fetch` from `path -> (status, payload)` or `path -> callable`."""
    import urllib.parse as _p

    def fetch(url, headers):
        if record is not None:
            record.append(url)
        split = _p.urlsplit(url)
        entry = table.get(split.path, default)
        if callable(entry):
            entry = entry(split.query, headers or {})
        status, payload, *rest = entry
        return Probed(status, rest[0] if rest else {}, body(payload))

    return fetch


def run_cli(argv, fetch):
    """Exercise the real CLI hermetically by pinning the default fetch seam."""
    original = custody_probe.default_fetch
    custody_probe.default_fetch = lambda timeout=10.0: fetch
    try:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(argv)
        return code, buffer.getvalue()
    finally:
        custody_probe.default_fetch = original


class TestTheLeakWeActuallyServe(unittest.TestCase):
    # -- 1 ------------------------------------------------------------------
    def test_1_detects_seed_in_json_response(self):
        fetch = responder({ONRAMP: (200, {
            "address": "nano_3f77", "seed": SEED, "index": 0, "onboard_id": 1,
        })})
        result = probe("https://x.invalid", fetch=fetch, paths=[ONRAMP])
        self.assertEqual(result["findings_total"], 2)
        patterns = {(f["pattern"], f.get("json_path"))
                    for f in result["paths"][0]["variants"]["plain"]["findings"]}
        self.assertIn(("json_key", "$.seed"), patterns)
        self.assertIn(("hex64", None), patterns)
        self.assertFalse(result["serves_no_key_material"])
        self.assertFalse(result["pass"])
        code, _ = run_cli(["https://x.invalid", "--paths", ONRAMP, "--quiet"], fetch)
        self.assertEqual(code, 1)

    # -- 2 ------------------------------------------------------------------
    def test_2_clean_origin_passes(self):
        table = {"/llms.txt": (200, "# llms.txt\nWe never send you a key.\n"),
                 ONRAMP: (410, {"error": "gone", "detail": "retired; bring your own address"})}
        fetch = responder(table)
        result = probe("https://x.invalid", fetch=fetch)
        self.assertEqual(result["findings_total"], 0)
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["pass"])
        code, out = run_cli(["https://x.invalid"], fetch)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["pass"], True)

    # -- 3 ------------------------------------------------------------------
    def test_3_probe_output_contains_no_key_material(self):
        """Constraint 4, and it is not optional."""
        fetch = responder({ONRAMP: (200, {"address": "nano_3f77", "seed": SEED}),
                           "/agent.json": (200, {"mnemonic": " ".join(["abandon"] * 24)}),
                           KEYGEN: (200, "var k = '%s';\n" % ALT_SEED)})
        result = probe("https://x.invalid", fetch=fetch)
        self.assertGreater(result["findings_total"], 0)
        serialised = json.dumps(result)
        self.assertNotIn(SEED, serialised)
        self.assertNotIn(ALT_SEED, serialised)
        self.assertNotIn(ALT_SEED.lower(), serialised)
        self.assertIsNone(custody_probe.HEX64_RE.search(serialised))


class TestTheProbeCanFail(unittest.TestCase):
    # -- 4 ------------------------------------------------------------------
    def test_4_self_test_requires_both_controls(self):
        """The test that would have caught the defect in nano-onramp-check.js."""
        with redirect_stdout(io.StringIO()):
            self.assertEqual(custody_probe.self_test(), 0)
        original = custody_probe.detect
        custody_probe.detect = lambda text, path, variant: {"findings": [], "excluded": []}
        try:
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(custody_probe.self_test(), 1)
            self.assertEqual(json.loads(out.getvalue())["self_test"], "fail")
        finally:
            custody_probe.detect = original
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--self-test"]), 0)


class TestTheVariantMatrix(unittest.TestCase):
    # -- 5 ------------------------------------------------------------------
    def test_5_leak_under_query_variant_only(self):
        def handler(query, headers):
            if "seed=1" in query:
                return (200, {"address": "nano_1", "seed": SEED})
            return (200, {"address": "nano_1"})

        result = probe("https://x.invalid", fetch=responder({ONRAMP: handler}), paths=[ONRAMP])
        self.assertFalse(result["pass"])
        variants = result["paths"][0]["variants"]
        self.assertEqual(variants["plain"]["findings"], [])
        found = variants["query_seed"]["findings"]
        self.assertTrue(found)
        self.assertEqual({f["variant"] for f in found}, {"query_seed"})

    # -- 6 ------------------------------------------------------------------
    def test_6_leak_under_accept_html_only(self):
        def handler(query, headers):
            if headers.get("Accept") == "text/html":
                return (200, "<pre>%s</pre>" % SEED)
            return (200, {"address": "nano_1"})

        result = probe("https://x.invalid", fetch=responder({ONRAMP: handler}), paths=[ONRAMP])
        self.assertFalse(result["pass"])
        found = result["paths"][0]["variants"]["accept_html"]["findings"]
        self.assertEqual([f["variant"] for f in found], ["accept_html"])
        self.assertEqual(result["paths"][0]["variants"]["accept_any"]["findings"], [])


class TestTheExclusionsMostLikelyToBeGotWrong(unittest.TestCase):
    # -- 7 ------------------------------------------------------------------
    def test_7_block_hash_is_not_a_finding(self):
        fetch = responder({"/agent.json": (200, {"paymentBlock": SEED, "verified": True})})
        result = probe("https://x.invalid", fetch=fetch, paths=["/agent.json"])
        self.assertEqual(result["findings_total"], 0)
        excluded = result["paths"][0]["excluded"]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]["key"], "paymentBlock")
        self.assertEqual(excluded[0]["reason"], "block_hash_key")
        self.assertTrue(result["pass"])

    # -- 8 ------------------------------------------------------------------
    def test_8_hex_in_a_comment_is_not_a_finding(self):
        commented = "// example only: %s\nexport function keygen() {}\n" % SEED
        result = probe("https://x.invalid", paths=[KEYGEN],
                       fetch=responder({KEYGEN: (200, commented)}))
        self.assertEqual(result["findings_total"], 0)
        self.assertEqual(result["paths"][0]["excluded"][0]["reason"], "comment_line")
        self.assertTrue(result["pass"])

        bare = "const k = '%s';\nexport function keygen() {}\n" % SEED
        moved = probe("https://x.invalid", paths=[KEYGEN],
                      fetch=responder({KEYGEN: (200, bare)}))
        self.assertEqual(moved["findings_total"], 1)
        self.assertEqual(moved["paths"][0]["variants"]["plain"]["findings"][0]["pattern"], "hex64")
        self.assertFalse(moved["pass"])

    # -- 9 ------------------------------------------------------------------
    def test_9_null_seed_key_is_not_a_finding(self):
        for value in (None, ""):
            with self.subTest(value=value):
                fetch = responder({"/agent.json": (200, {"seed": value, "address": "nano_1"})})
                result = probe("https://x.invalid", fetch=fetch, paths=["/agent.json"])
                self.assertEqual(result["findings_total"], 0)
                self.assertEqual(result["paths"][0]["excluded"][0]["reason"],
                                 "documented_key_with_no_value")
                self.assertTrue(result["pass"])

    # -- 18 -----------------------------------------------------------------
    def test_18_bip39_shape_detected(self):
        words = " ".join(["abandon", "ability", "able", "about", "above", "absent",
                          "absorb", "abstract", "absurd", "abuse", "access",
                          "accident", "account", "accuse", "achieve", "acid",
                          "acoustic", "acquire", "across", "act", "action",
                          "actor", "actress", "actual"])
        fetch = responder({"/agent.json": (200, {"note": words})})
        result = probe("https://x.invalid", fetch=fetch, paths=["/agent.json"])
        found = result["paths"][0]["variants"]["plain"]["findings"]
        self.assertEqual([f["pattern"] for f in found], ["bip39_shape"])
        self.assertEqual(found[0]["word_count"], 24)
        self.assertFalse(result["pass"])


class TestWhatCountsAsMeasured(unittest.TestCase):
    # -- 10 -----------------------------------------------------------------
    def test_10_retired_endpoint_is_a_pass(self):
        retirement = {"error": "gone",
                      "detail": "This endpoint is retired. Bring your own address."}
        result = probe("https://x.invalid", paths=[ONRAMP],
                       fetch=responder({ONRAMP: (410, retirement)}))
        self.assertEqual(result["paths"][0]["state"], "retired")
        self.assertEqual(result["findings_total"], 0)
        self.assertTrue(result["pass"])

    # -- 11 -----------------------------------------------------------------
    def test_11_absent_path_is_not_a_failure(self):
        result = probe("https://x.invalid",
                       fetch=responder({"/llms.txt": (200, "# llms.txt\n")}))
        states = {p["path"]: p["state"] for p in result["paths"]}
        self.assertEqual(states["/llms.txt"], "answered")
        self.assertEqual(states[ONRAMP], "absent")
        self.assertTrue(result["pass"])

    # -- 12 -----------------------------------------------------------------
    def test_12_silent_origin_cannot_pass(self):
        result = probe("https://x.invalid", fetch=responder({}))
        self.assertEqual(result["findings_total"], 0)
        self.assertTrue(result["serves_no_key_material"])
        self.assertFalse(result["pass"], "an origin that answers nothing must not pass")


class TestErrorsAreNeverAPass(unittest.TestCase):
    # -- 13 -----------------------------------------------------------------
    def test_13_unreachable_origin_is_an_error_not_a_pass(self):
        def fetch(url, headers):
            raise OSError("connection refused")

        result = probe("https://x.invalid", fetch=fetch, paths=[ONRAMP])
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["code"], "unreachable")
        self.assertEqual(result["errors"][0]["path"], ONRAMP)
        self.assertFalse(result["pass"])
        code, _ = run_cli(["https://x.invalid", "--paths", ONRAMP, "--quiet"], fetch)
        self.assertEqual(code, 1)

    def test_13b_timeout_is_reported_as_a_timeout(self):
        def fetch(url, headers):
            raise TimeoutError("timed out")

        result = probe("https://x.invalid", fetch=fetch, paths=[ONRAMP])
        self.assertEqual(result["errors"][0]["code"], "timeout")
        self.assertFalse(result["pass"])

    # -- 14 -----------------------------------------------------------------
    def test_14_http_origin_fails(self):
        result = probe("http://x.invalid", paths=["/llms.txt"],
                       fetch=responder({"/llms.txt": (200, "# clean\n")}))
        self.assertTrue(result["insecure_transport"])
        self.assertEqual(result["findings_total"], 0)
        self.assertFalse(result["pass"], "a key sent in clear text is worse, not better")

    # -- 15 -----------------------------------------------------------------
    def test_15_offsite_redirect_is_not_followed(self):
        seen = []
        fetch = responder({ONRAMP: (302, b"", {"Location": "https://elsewhere.invalid/x"})},
                          record=seen)
        result = probe("https://x.invalid", fetch=fetch, paths=[ONRAMP])
        self.assertEqual(result["errors"][0]["code"], "offsite_redirect")
        self.assertEqual(result["errors"][0]["origin"], "https://elsewhere.invalid")
        self.assertFalse(result["pass"])
        self.assertEqual(seen, ["https://x.invalid" + ONRAMP])

    def test_15b_same_origin_redirect_loop_is_an_error(self):
        fetch = responder({ONRAMP: (302, b"", {"Location": ONRAMP})})
        result = probe("https://x.invalid", fetch=fetch, paths=[ONRAMP])
        self.assertEqual(result["errors"][0]["code"], "redirect_loop")
        self.assertFalse(result["pass"])

    # -- 16 -----------------------------------------------------------------
    def test_16_body_too_large_refuses_to_conclude(self):
        huge = b"." * (MAX_BODY_BYTES + 1024 * 1024)
        result = probe("https://x.invalid", paths=["/llms.txt"],
                       fetch=responder({"/llms.txt": (200, huge)}))
        self.assertEqual(result["errors"][0]["code"], "body_too_large")
        self.assertEqual(result["findings_total"], 0)
        self.assertFalse(result["pass"], "a leak could be past the cut")

    def test_16b_five_hundreds_everywhere_is_an_origin_error(self):
        result = probe("https://x.invalid", fetch=responder({}, default=(503, b"down")))
        codes = [e["code"] for e in result["errors"]]
        self.assertIn("origin_error", codes)
        self.assertFalse(result["pass"])

    def test_16c_unparseable_origin_raises_and_the_cli_exits_2(self):
        for bad in ("", "   ", "ftp://x.invalid"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    probe(bad, fetch=responder({}))
        self.assertEqual(main(["ftp://x.invalid", "--quiet"]), 2)
        self.assertEqual(main(["--quiet"]), 2)

    def test_16d_a_bare_host_is_normalised_to_https(self):
        self.assertEqual(normalise_origin("getunstuck.space"),
                         ("https://getunstuck.space", False))
        self.assertEqual(normalise_origin("http://h.invalid"), ("http://h.invalid", True))


class TestTheBuildRules(unittest.TestCase):
    # -- 17 -----------------------------------------------------------------
    def test_17_no_network_imports(self):
        graph = import_graph(os.path.join(ROOT, "custody_probe.py"))
        self.assertTrue(graph)
        for entry in graph:
            root = entry["module"].split(".")[0]
            with self.subTest(module=entry["module"]):
                self.assertIn(root, sys.stdlib_module_names,
                              "%s is outside the standard library" % entry["module"])
        network = [e for e in graph if e["module"] in NETWORK_MODULES]
        self.assertTrue(network, "the default fetch has to reach the network somehow")
        self.assertEqual({e["function"] for e in network}, {"default_fetch"})
        top_level = {e["module"] for e in graph if e["function"] is None}
        self.assertEqual(top_level & NETWORK_MODULES, set())

    def test_17b_probe_with_an_injected_fetch_never_imports_the_network_layer(self):
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "import custody_probe as c\n"
            "c.probe('https://x.invalid', fetch=lambda u, h: c.Probed(404, {}, b''))\n"
            "bad = sorted(m for m in ('urllib.request', 'http.client', 'socket', 'ssl')\n"
            "             if m in sys.modules)\n"
            "print(','.join(bad))\n" % ROOT
        )
        out = subprocess.run([sys.executable, "-c", script], capture_output=True,
                             text=True, timeout=60, check=True)
        self.assertEqual(out.stdout.strip(), "")

    def test_17c_no_key_material_stands_in_the_source_of_this_build(self):
        for name in ("custody_probe.py", os.path.join("tests", "test_custody_probe.py")):
            with open(os.path.join(ROOT, name), "r", encoding="utf-8") as handle:
                text = handle.read()
            with self.subTest(file=name):
                self.assertIsNone(custody_probe.HEX64_RE.search(text))

    def test_17d_the_default_path_list_is_the_one_the_spec_names(self):
        self.assertEqual(len(DEFAULT_PATHS), 11)
        self.assertIn(ONRAMP, DEFAULT_PATHS)
        self.assertEqual(len(set(DEFAULT_PATHS)), len(DEFAULT_PATHS))

    # -- 19 -----------------------------------------------------------------
    def test_19_findings_are_stable_and_ordered(self):
        """Two runs of the same fixture diff to nothing, so an outsider can diff ours."""
        fetch = responder({ONRAMP: (200, {"seed": SEED, "address": "nano_1"}),
                           "/llms.txt": (200, "# llms.txt\n"),
                           "/agent.json": (200, {"paymentBlock": ALT_SEED})})
        original = custody_probe._utc_now
        custody_probe._utc_now = lambda: "2026-09-30T06:00:00Z"
        try:
            first = json.dumps(probe("https://x.invalid", fetch=fetch), indent=2)
            second = json.dumps(probe("https://x.invalid", fetch=fetch), indent=2)
        finally:
            custody_probe._utc_now = original
        self.assertEqual(first, second)
        self.assertIn('"measured_at": "2026-09-30T06:00:00Z"', first)


if __name__ == "__main__":
    unittest.main()
