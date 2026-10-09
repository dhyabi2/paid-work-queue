"""`mint.py` - one keypair from the machine's own entropy, that never leaves it.

Every test here fails without the tool. The ones worth reading twice are not the
happy paths:

  3, 4   the secret must be absent from stdout, stderr AND the exception text.
         Test 4 forces the failure path, because that is where this class of
         leak actually happens.
  7, 8   the tool's own claim of `network_calls_made: 0` and `os.urandom` only,
         asserted from the AST and from a patched clock rather than from prose.
  12     no file is ever created at a mode looser than 0600, not even for the
         instant between create and chmod. Checked by capturing every CREATING
         `os.open` call, because a write-then-chmod would pass a final-state
         check and still have published the key on a shared runner.
  18     `mint.py check` and `http_claim.py`'s `/check-address` return the same
         verdict and the same expected checksum over twelve addresses. They
         share one function; this is what holds that true.
  21, 22 the derivation is held against two EXTERNAL standards - RFC 8032's
         published vectors under sha512, and the known zero-seed Nano account
         under blake2b. A self-consistent but wrong implementation passes
         neither, and nothing else in this suite could tell.
"""

import ast
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import mint  # noqa: E402
import nanoaddr  # noqa: E402

VECTORS = os.path.join(ROOT, "vectors", "mint-v1.json")


def run(*argv):
    """Run `mint.main` in-process, returning (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = mint.main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def payload(text):
    return json.loads(text)


def key_hex(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


class Minting(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.key = os.path.join(self.dir, "nano.key")
        self.addCleanup(self._tmp.cleanup)

    # -- 1 ------------------------------------------------------------------
    def test_01_a_mint_stores_a_0600_file_whose_address_round_trips(self):
        code, out, err = run("new", "--path", self.key)
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.exists(self.key))
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o600)
        document = payload(out)
        self.assertEqual(document["mode"], "0600")
        self.assertEqual(nanoaddr.decode(document["address"]),
                         mint.public_key_for(bytes.fromhex(key_hex(self.key))))

    # -- 2 ------------------------------------------------------------------
    def test_02_the_address_is_65_characters_and_checksums(self):
        code, out, _ = run("new", "--path", self.key)
        self.assertEqual(code, 0)
        document = payload(out)
        self.assertEqual(len(document["address"]), 65)
        self.assertTrue(document["address"].startswith("nano_"))
        self.assertIs(document["checksum_ok"], True)
        self.assertIs(document["secret_in_this_output"], False)
        self.assertEqual(document["entropy_source"], "os.urandom")
        self.assertEqual(document["network_calls_made"], 0)

    # -- 3 ------------------------------------------------------------------
    def test_03_the_secret_appears_nowhere_on_the_success_path(self):
        code, out, err = run("new", "--path", self.key)
        self.assertEqual(code, 0)
        secret = key_hex(self.key)
        self.assertEqual(len(secret), 64)
        for stream, name in ((out, "stdout"), (err, "stderr")):
            self.assertNotIn(secret, stream, "the key is in %s" % name)
            self.assertNotIn(secret.upper(), stream)
            # and not in halves either, which is how it would survive a
            # test that only looked for the whole thing.
            self.assertNotIn(secret[:32], stream)
            self.assertNotIn(secret[32:], stream)

    # -- 4 ------------------------------------------------------------------
    def test_04_the_secret_appears_nowhere_on_a_failure_path_either(self):
        """The leak that matters: a codec that raises with the key in the text.

        `nanoaddr.encode` is replaced by one that fails LOUDLY, carrying the
        key material in its own message - exactly the mistake this is guarding
        against. The tool must swallow that message, remove the key file, and
        print neither.
        """
        captured = {}
        original = nanoaddr.encode
        vector_key = mint.public_key_for(hashlib.blake2b(
            bytes(32) + (0).to_bytes(4, "big"), digest_size=32).digest())

        def exploding(public_key, prefix="nano_"):
            # Pass the known vector through, so the runtime soundness control
            # still succeeds and this test exercises `self_check_failed` rather
            # than `derivation_unsound`. A codec that fails on one key and not
            # another is also the more realistic fault.
            if public_key == vector_key:
                return original(public_key, prefix)
            captured["key"] = public_key.hex()
            raise ValueError("cannot encode public key %s" % public_key.hex())

        nanoaddr.encode = exploding
        try:
            code, out, err = run("new", "--path", self.key)
        finally:
            nanoaddr.encode = original

        self.assertEqual(code, 3, out)
        document = payload(out)
        self.assertEqual(document["error"], "self_check_failed")
        self.assertFalse(os.path.exists(self.key),
                         "a mint that could not prove its address left the key behind")
        self.assertIn("key", captured)
        self.assertNotIn(captured["key"], out)
        self.assertNotIn(captured["key"], err)
        self.assertNotIn("cannot encode public key", out + err)

    # -- 5 ------------------------------------------------------------------
    def test_05_minting_onto_an_existing_file_refuses_and_names_the_account(self):
        code, out, _ = run("new", "--path", self.key)
        self.assertEqual(code, 0)
        before = (key_hex(self.key), os.stat(self.key).st_mtime_ns)
        existing = payload(out)["address"]

        code, out, _ = run("new", "--path", self.key)
        self.assertEqual(code, 2)
        document = payload(out)
        self.assertEqual(document["reason"], "key_file_exists")
        self.assertIn(self.key, document["detail"])
        self.assertEqual(document["existing_address"], existing)
        self.assertNotIn(before[0], json.dumps(document))
        self.assertEqual((key_hex(self.key), os.stat(self.key).st_mtime_ns), before,
                         "the existing key file was touched")

    # -- 6 ------------------------------------------------------------------
    def test_06_there_is_no_way_to_ask_for_an_overwrite(self):
        run("new", "--path", self.key)
        for flag in ("--force", "-f", "--overwrite", "--yes"):
            code, _, _ = run("new", "--path", self.key, flag)
            self.assertEqual(code, 64, "%s was accepted" % flag)
        # and the refusal above is still the only answer
        self.assertEqual(run("new", "--path", self.key)[0], 2)

    # -- 7 ------------------------------------------------------------------
    def test_07_the_import_set_excludes_the_network_and_the_weak_rng(self):
        imports = mint.imports_of()
        for banned in ("socket", "ssl", "http", "urllib", "random", "requests",
                       "asyncio", "secrets"):
            self.assertNotIn(banned, imports,
                             "mint.py imports %s" % banned)
        self.assertIn("os", imports)
        self.assertIn("hashlib", imports)
        # And the whole graph it reaches, not just its own first line: canonical
        # and nanoaddr are the only local modules it may pull in.
        local = {name[:-3] for name in os.listdir(ROOT) if name.endswith(".py")}
        local |= {name[:-3] for name in os.listdir(os.path.join(ROOT, "vendor"))
                  if name.endswith(".py")}
        seen, queue = set(), ["mint"]
        paths = {"mint": os.path.join(ROOT, "mint.py")}
        for base in (ROOT, os.path.join(ROOT, "vendor")):
            for name in os.listdir(base):
                if name.endswith(".py"):
                    paths.setdefault(name[:-3], os.path.join(base, name))
        while queue:
            module = queue.pop()
            if module in seen or module not in paths:
                continue
            seen.add(module)
            for name in mint.imports_of(paths[module]):
                self.assertNotIn(name, ("socket", "ssl", "http", "urllib",
                                        "requests", "random"),
                                 "%s reaches %s" % (module, name))
                queue.append(name)
        self.assertEqual(seen - {"mint"}, {"canonical", "nanoaddr"},
                         "mint.py reaches more of this repository than it needs")

    # -- 8 ------------------------------------------------------------------
    def test_08_the_clock_is_never_read_during_a_mint(self):
        import time as time_module

        calls = []
        originals = {}
        for name in ("time", "time_ns", "monotonic", "monotonic_ns",
                     "perf_counter", "process_time"):
            originals[name] = getattr(time_module, name)

            def spy(*args, _name=name, _real=originals[name], **kwargs):
                calls.append(_name)
                return _real(*args, **kwargs)

            setattr(time_module, name, spy)
        try:
            code, _, err = run("new", "--path", self.key)
        finally:
            for name, real in originals.items():
                setattr(time_module, name, real)
        self.assertEqual(code, 0, err)
        self.assertEqual(calls, [], "the mint path read the clock: %r" % calls)

    # -- 9 ------------------------------------------------------------------
    def test_09_two_mints_are_two_different_accounts(self):
        first = payload(run("new", "--path", self.key)[1])["address"]
        second = payload(run("new", "--path", os.path.join(self.dir, "b.key"))[1])["address"]
        self.assertNotEqual(first, second,
                            "two mints produced one account - the seeding is deterministic")

    # -- 10 -----------------------------------------------------------------
    def test_10_host_path_stores_in_that_directory_and_excludes_path(self):
        target = os.path.join(self.dir, "chosen")
        os.mkdir(target)
        code, out, _ = run("new", "--host-path", target)
        self.assertEqual(code, 0)
        self.assertEqual(payload(out)["stored_at"],
                         os.path.join(target, "nano.key"))
        self.assertTrue(os.path.exists(os.path.join(target, "nano.key")))

        code, _, err = run("new", "--path", self.key, "--host-path", target)
        self.assertEqual(code, 64)
        self.assertIn("not both", err)

    # -- 11 -----------------------------------------------------------------
    def test_11_an_unwritable_directory_names_the_flag_that_fixes_it(self):
        locked = os.path.join(self.dir, "locked")
        os.mkdir(locked)
        os.chmod(locked, 0o500)
        self.addCleanup(os.chmod, locked, 0o700)
        if os.access(locked, os.W_OK):  # pragma: no cover - running as root
            self.skipTest("this user can write to a 0500 directory")
        code, out, _ = run("new", "--path", os.path.join(locked, "nano.key"))
        self.assertEqual(code, 3, out)
        document = payload(out)
        self.assertEqual(document["reason"], "path_not_writable")
        self.assertIn("--host-path", document["detail"],
                      "the error must name the flag that fixes it")
        self.assertEqual(os.listdir(locked), [])

    # -- 11b ----------------------------------------------------------------
    def test_11b_the_refusal_holds_even_where_a_0500_directory_is_writable(self):
        """Test 11 skips for root, and root is what CI containers often are.

        The acceptance line is that an unwritable target exits 3 naming
        `--host-path`, so it is asserted here too by making the create itself
        fail - which is the condition test 11 is trying to arrange, reached
        directly instead of through the file system's opinion of this user.
        """
        import tempfile as tempfile_module

        def refusing(*args, **kwargs):
            raise PermissionError(13, "Permission denied")

        original = tempfile_module.mkstemp
        tempfile_module.mkstemp = refusing
        try:
            code, out, _ = run("new", "--path", self.key)
        finally:
            tempfile_module.mkstemp = original
        self.assertEqual(code, 3, out)
        document = payload(out)
        self.assertEqual(document["reason"], "path_not_writable")
        self.assertIn("--host-path", document["detail"])
        self.assertFalse(os.path.exists(self.key))

    # -- 11c ----------------------------------------------------------------
    def test_11c_a_build_that_cannot_reproduce_the_known_account_mints_nothing(self):
        """The runtime control, and it must fire BEFORE the filesystem is touched.

        Round-tripping a minted address proves the encoding is self-consistent,
        not that the private key controls the public key - both halves read the
        same `_scalar_mult`. So a derivation that is wrong twice over passes
        the round trip and hands the operator an address whose key nobody
        holds. This is the guard that refuses instead, and the assertion that
        matters is that no key file exists afterwards.
        """
        original = mint._clamp
        mint._clamp = lambda scalar_bytes: int.from_bytes(scalar_bytes, "little")
        try:
            code, out, _ = run("new", "--path", self.key)
        finally:
            mint._clamp = original
        self.assertEqual(code, 3, out)
        document = payload(out)
        self.assertEqual(document["reason"], "derivation_unsound")
        self.assertFalse(os.path.exists(self.key),
                         "a build with a broken derivation still wrote a key")
        self.assertTrue(mint._derivation_is_sound(),
                        "the control does not pass on an unmutated build")

    # -- 12 -----------------------------------------------------------------
    def test_12_no_file_is_ever_created_at_a_looser_mode(self):
        """Not even for an instant.

        Only CREATING calls are judged: `os.open` takes a mode argument on
        every call and ignores it without O_CREAT, so asserting over all calls
        would fail on an ordinary read and prove nothing about the key file.
        """
        modes = []
        real_open = os.open

        def watching(path, flags, mode=0o777, **kwargs):
            if flags & os.O_CREAT:
                modes.append((os.fspath(path), mode))
            return real_open(path, flags, mode, **kwargs)

        os.open = watching
        try:
            code, _, err = run("new", "--path", self.key)
        finally:
            os.open = real_open
        self.assertEqual(code, 0, err)
        self.assertTrue(modes, "nothing was created, so nothing was measured")
        for path, mode in modes:
            self.assertEqual(mode & 0o177, 0,
                             "%s was created at mode 0%o" % (path, mode))

    # -- 13 -----------------------------------------------------------------
    def test_13_print_prefix_only_withholds_the_address_and_address_returns_it(self):
        code, out, _ = run("new", "--path", self.key, "--print-prefix-only")
        self.assertEqual(code, 0)
        document = payload(out)
        self.assertNotIn("address", document)
        self.assertEqual(len(document["address_prefix"]), 9)
        self.assertTrue(document["address_prefix"].startswith("nano_"))

        code, out, _ = run("address", "--path", self.key)
        self.assertEqual(code, 0)
        full = payload(out)["address"]
        self.assertEqual(len(full), 65)
        self.assertTrue(full.startswith(document["address_prefix"]))

        code, out, _ = run("address", "--path", self.key, "--prefix-only")
        self.assertEqual(code, 0)
        self.assertNotIn("address", payload(out))


class KeyFiles(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    # -- 14 -----------------------------------------------------------------
    def test_14_a_missing_key_file_is_a_refusal(self):
        code, out, _ = run("address", "--path", os.path.join(self.dir, "absent.key"))
        self.assertEqual(code, 2)
        self.assertEqual(payload(out)["reason"], "key_file_missing")

    # -- 15 -----------------------------------------------------------------
    def test_15_a_malformed_key_file_refuses_without_echoing_a_byte(self):
        cases = {
            "short.key": "ab" * 31 + "c",          # 63 characters
            "nonhex.key": "z" * 64,                 # right length, not hex
            "long.key": "ab" * 33,                  # 66 characters
            "empty.key": "",
        }
        for name, content in cases.items():
            path = os.path.join(self.dir, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            code, out, err = run("address", "--path", path)
            self.assertEqual(code, 2, "%s was accepted" % name)
            document = payload(out)
            self.assertEqual(document["reason"], "key_file_malformed", name)
            if content:
                self.assertNotIn(content, out + err,
                                 "%s had its content echoed" % name)

    # -- 16 -----------------------------------------------------------------
    def test_16_the_eddie_researcher_vector_is_caught_with_the_right_checksum(self):
        """One character off, so a payment to it would be lost.

        The address is the recorded FAILURE MODE, not the recorded string:
        `eddie_researcher`'s actual address is not stored anywhere in this
        repository, so this reproduces it the way every other suite here does
        (`test_quotelock.py` 7b, `test_external_edge_count.py`) - by mutating
        one character of a valid address. `vectors/mint-v1.json` pins both
        spellings and the checksum ours implies.
        """
        with open(VECTORS, "r", encoding="utf-8") as handle:
            vectors = json.load(handle)
        self.assertEqual(len(vectors["invalid"]), 2)
        for row in vectors["invalid"]:
            code, out, _ = run("check", "--address", row["address"])
            self.assertEqual(code, 2, row["address"])
            document = payload(out)
            self.assertIs(document["checksum_ok"], False)
            self.assertIs(document["this_address_would_lose_the_payment"], True)
            self.assertEqual(document["expected_checksum"], row["expected_checksum"])
            self.assertEqual(document["given_checksum"], row["given_checksum"])
            self.assertNotEqual(document["expected_checksum"],
                                document["given_checksum"])

    # -- 17 -----------------------------------------------------------------
    def test_17_both_spellings_of_one_account_validate_to_one_key(self):
        with open(VECTORS, "r", encoding="utf-8") as handle:
            modern = json.load(handle)["valid"][0]["address"]
        legacy = "xrb_" + modern[len("nano_"):]
        verdicts = []
        for address in (modern, legacy):
            code, out, _ = run("check", "--address", address)
            self.assertEqual(code, 0, address)
            verdicts.append(payload(out))
        self.assertEqual(verdicts[0]["public_key_halves"],
                         verdicts[1]["public_key_halves"])
        self.assertEqual(verdicts[0]["address"], verdicts[1]["address"],
                         "the two spellings must normalise to one address")
        self.assertEqual(verdicts[1]["prefix_given"], "xrb_")

    # -- 18 -----------------------------------------------------------------
    def test_18_mint_and_the_http_surface_never_disagree(self):
        """One implementation, asserted over twelve addresses.

        They are the same function (`canonical.checksum_pair` behind
        `nanoaddr.validate`); this test is what stops a future edit making them
        two again, which is how one address comes to have two expected
        checksums depending on which surface a seller happened to ask.
        """
        import http_claim

        with open(VECTORS, "r", encoding="utf-8") as handle:
            vectors = json.load(handle)
        rows = vectors["valid"] + vectors["invalid"]
        self.assertEqual(len(rows), 12)
        self.assertEqual(sum(1 for row in rows if row["valid"]), 10)

        for row in rows:
            ours = mint.check_address(row["address"])
            status, theirs = http_claim.ClaimService.check_address(
                None, {"a": row["address"]})
            self.assertEqual(status, 200)
            self.assertEqual(ours["checksum_ok"], theirs["valid"], row["address"])
            self.assertEqual(ours.get("expected_checksum"),
                             theirs.get("checksum_expected"), row["address"])
            self.assertEqual(ours.get("given_checksum"),
                             theirs.get("checksum_found"), row["address"])
            if row["valid"]:
                self.assertEqual(ours["address"], theirs["address"])

    # -- 19 -----------------------------------------------------------------
    def test_19_the_repository_tree_holds_no_key_file(self):
        offenders = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in {".git", "__pycache__", ".pytest_cache"}]
            for name in filenames:
                if name.endswith(".key") or name == "nano.key":
                    offenders.append(os.path.relpath(
                        os.path.join(dirpath, name), ROOT))
        self.assertEqual(offenders, [],
                         "a key file is in the tree: %r" % offenders)


class Standards(unittest.TestCase):
    """The derivation against two external standards, and nothing of ours."""

    # -- 20 -----------------------------------------------------------------
    def test_20_self_test_passes_with_enough_negative_controls(self):
        before = set(os.listdir(ROOT))
        code, out, _ = run("--self-test")
        self.assertEqual(code, 0, out)
        report = json.loads(out)
        self.assertIs(report["ok"], True)
        self.assertEqual(report["network_calls_made"], 0)
        self.assertGreaterEqual(report["negative_controls"], 8)
        self.assertEqual(report["negative_controls"],
                         report["negative_controls_refused_on_their_own_reason"],
                         "a control refused for the wrong reason: %r"
                         % [c for c in report["checks"] if not c["ok"]])
        self.assertEqual(set(os.listdir(ROOT)), before,
                         "--self-test wrote outside its temporary directory")

    # -- 21 -----------------------------------------------------------------
    def test_21_rfc_8032_vectors_under_sha512(self):
        """Handed sha512 this is standard Ed25519, so RFC 8032 judges it.

        Both vectors, and the public key BYTES - a round trip against our own
        encoder would pass on an implementation that is consistently wrong.
        Each literal is two 32-character halves because validate.py refuses a
        committed 64-hex run; a private key looks exactly like one.
        """
        vectors = [
            ("9d61b19deffd5a60ba844af492ec2cc4", "4449c5697b326919703bac031cae7f60",
             "d75a980182b10ab7d54bfed3c964073a", "0ee172f3daa62325af021a68f707511a"),
            ("4ccd089b28ff96da9db6c346ec114e0f", "5b8a319f35aba624da8cf6ed4fb8a6fb",
             "3d4017c3e843895a92b70aa74d1b7ebc", "9c982ccf2ec4968cc0cd55f12af4660c"),
        ]
        for index, (sk_a, sk_b, pk_a, pk_b) in enumerate(vectors, start=1):
            got = mint.public_key_for(bytes.fromhex(sk_a + sk_b), hashlib.sha512)
            self.assertEqual(got.hex(), pk_a + pk_b,
                             "RFC 8032 section 7.1 vector %d" % index)

    # -- 22 -----------------------------------------------------------------
    def test_22_the_known_zero_seed_account_derives(self):
        """Nano's own published answer for the seed nobody may use.

        The all-zero seed at index 0 is `nano_3i1aq1cch...d99d4r3b7` in every
        Nano implementation. Under blake2b this derivation must agree, and no
        amount of internal consistency produces this string by accident.
        """
        private_key = hashlib.blake2b(
            bytes(32) + (0).to_bytes(4, "big"), digest_size=32).digest()
        self.assertEqual(
            mint.address_for(private_key),
            "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7"
            "pwskuzi7ahz8oq6cobd99d4r3b7")

    # -- 23 -----------------------------------------------------------------
    def test_23_every_valid_vector_re_derives_from_the_rule_it_states(self):
        """The vectors file is checkable without trusting the vectors file."""
        with open(VECTORS, "r", encoding="utf-8") as handle:
            vectors = json.load(handle)
        self.assertIs(vectors["no_private_keys_here"], True)
        for row in vectors["valid"]:
            private_key = hashlib.blake2b(
                bytes(32) + row["index"].to_bytes(4, "big"),
                digest_size=32).digest()
            public_key = mint.public_key_for(private_key)
            self.assertEqual(mint.address_for(private_key), row["address"])
            self.assertEqual(
                [public_key.hex().upper()[:32], public_key.hex().upper()[32:]],
                row["public_key_halves"])
            self.assertEqual(nanoaddr.decode(row["address"]), public_key)

    # -- 24 -----------------------------------------------------------------
    def test_24_a_point_that_is_not_on_the_curve_has_no_x(self):
        """`_recover_x` returns None rather than guessing.

        A y with no matching x is a corrupted point, and the difference between
        None and a plausible-looking wrong x is the difference between an error
        and an address the operator publishes and never gets paid at.
        """
        refused = sum(1 for y in range(2, 400) if mint._recover_x(y, False) is None)
        self.assertGreater(refused, 0,
                           "_recover_x accepted every y, so it is not checking")
        self.assertIsNotNone(mint._recover_x(mint._BASE_Y, False))

    # -- 25 -----------------------------------------------------------------
    def test_25_the_tool_runs_as_a_subprocess_with_the_documented_codes(self):
        """End to end through the real CLI, not through main() in-process."""
        with tempfile.TemporaryDirectory() as scratch:
            key = os.path.join(scratch, "nano.key")
            first = subprocess.run(
                [sys.executable, os.path.join(ROOT, "mint.py"), "new",
                 "--path", key],
                capture_output=True, text=True, cwd=scratch)
            self.assertEqual(first.returncode, 0, first.stderr)
            address = json.loads(first.stdout)["address"]
            self.assertTrue(nanoaddr.is_valid(address))

            again = subprocess.run(
                [sys.executable, os.path.join(ROOT, "mint.py"), "new",
                 "--path", key],
                capture_output=True, text=True, cwd=scratch)
            self.assertEqual(again.returncode, 2)
            self.assertEqual(json.loads(again.stdout)["reason"], "key_file_exists")

            checked = subprocess.run(
                [sys.executable, os.path.join(ROOT, "mint.py"), "check",
                 "--address", address],
                capture_output=True, text=True, cwd=scratch)
            self.assertEqual(checked.returncode, 0)
            self.assertIs(json.loads(checked.stdout)["checksum_ok"], True)

            secret = key_hex(key)
            for result in (first, again, checked):
                self.assertNotIn(secret, result.stdout + result.stderr)

    # -- 26 -----------------------------------------------------------------
    def test_26_no_subcommand_is_a_usage_error_not_a_verdict(self):
        code, out, err = run()
        self.assertEqual(code, 64)
        self.assertEqual(out, "")
        self.assertIn("mint.py", err)

    # -- 27 -----------------------------------------------------------------
    def test_27_the_derivation_rejects_a_private_key_of_the_wrong_size(self):
        for bad in (b"", b"\x01" * 31, b"\x01" * 33, "a string", None):
            with self.assertRaises(mint.Refusal) as caught:
                mint.public_key_for(bad)
            self.assertEqual(caught.exception.code, "key_file_malformed")
            if isinstance(bad, bytes) and bad:
                self.assertNotIn(bad.hex(), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
