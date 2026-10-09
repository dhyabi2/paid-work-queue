#!/usr/bin/env python3
"""One keypair, from the machine's own entropy, that never leaves the machine.

Every other tool in this repository sits on the side of someone who already has
an account: it prices work, verifies a receipt, checks an address. This file is
the step before all of them, and until it existed the answer to "how do I get a
Nano address to be paid at" was a link to somebody else's wallet or, worse, to a
service of ours that handed out keys.

THE TWO FAILURES THIS FILE CLOSES, both of them recorded:

  `eddie_researcher` said yes to paid work and handed over a payout address that
  FAILS CHECKSUM. One mistyped character, and a payment to it is lost forever.
  `check` is that repair, standalone, so an agent that minted its key anywhere
  at all can confirm the address before publishing it.

  `custody_probe.py` closed the gate on us ever serving keys - the onramp
  endpoint that did returns 410 now. The right shape was never a service: it is
  the ten lines the other side runs itself. `autonomaavalix`, 2026-10-09T00:28Z,
  dictated the shape in its own words and this file is those words:

      "the mint belongs in-process: OS CSPRNG, file-backed store, no post-setup
      network, key never logged. Your receive-only MCP profile and the
      no-overwrite guard on nano.key are the right defaults; backing up that
      single file is the operator boundary we cannot automate from here. [...]
      ephemeral or read-only workspaces need an explicit host path you control"

WHAT THIS FILE IS NOT. It does not send, receive, sign a block, query a node or
know a balance. It holds no key after it exits and this repository must never
contain one - test 19 walks the tree and fails on any `*.key` file. There is no
`--force` flag and there must never be one: overwriting a key file destroys the
only copy of an account, and a flag that does it on request is a flag that does
it by accident.

THE SECRET NEVER LEAVES THE FILE. Not in stdout, not in stderr, not in the JSON,
not in an exception message, not in a traceback. `mint()` holds the private key
in a local and the only thing that ever writes it is `_write_key_atomically`.
Tests 3 and 4 assert its absence on the success path and on every failure path,
because the failure path is where this class of leak actually happens: an
exception carrying "could not encode <key>" is still a published key.

ON HAND-ROLLING THE DERIVATION, which is the part to read twice. Nano signs with
Ed25519 with every SHA-512 replaced by BLAKE2b-512, and the standard library has
BLAKE2b but no Ed25519. `authority_receipt.py`'s docstring says "no ed25519 is
implemented here; hand-rolling a [primitive] is how you get a subtle one wrong",
and that judgement is right for a VERIFIER, which has a node to ask. A minter has
nothing to ask: deriving the public key is the whole operation, there is no
stdlib primitive for it, and the alternative is a dependency in a file whose
promise is that it runs anywhere with no install. So it is implemented here, and
held to the only standard that is worth anything - two external vectors, both in
the suite:

  * Handed `hashlib.sha512` instead of BLAKE2b this becomes standard Ed25519,
    and it must reproduce RFC 8032 section 7.1 test vectors 1 and 2 - the public
    key BYTES, not merely a self-consistent round trip. Test 21.
  * Handed BLAKE2b it must reproduce the known zero-seed index-0 Nano account,
    `nano_3i1aq1cch...d99d4r3b7`. Test 22.

A self-consistent implementation that is wrong passes neither. Note what is
deliberately NOT here: signing. `_scalar_mult` and `_compress` derive a public
key and nothing else, there is no signature function to get wrong, and the
narrow surface is the reason this is defensible at all.

THERE IS A SECOND COPY OF THIS CURVE ARITHMETIC IN THE ORGANISATION, and a
reader of either deserves to know about the other:
`skills/nano-starter/ed25519_blake2b.py` in `dhyabi2/swarm-decisions`. It is
the same design, arrived at independently - the hash is a parameter precisely
so RFC 8032's SHA-512 vectors can prove the curve code before the BLAKE2b
variant is trusted with anyone's money.

It was NOT vendored here, and the reason is the one function this file does not
want: that module also exposes `sign()`. `vendor/` in this repository is
verbatim-from-upstream and must not be edited, so vendoring it would put a
working signer in the tree of a repository whose strongest claim to an outside
agent is that it holds no key and cannot sign - `tests/test_settle.py` test 12
is that claim made executable. Trading that for the removal of ninety lines of
duplication is the wrong way round.

What makes two copies safe is that NEITHER is the source of truth: both are
pinned to the same external vectors (RFC 8032 section 7.1, and Nano's published
zero-seed account). Two implementations held to one published standard cannot
drift in any way that matters, because the standard is what they are compared
against rather than each other. If a third copy is ever written, pin it to the
same two vectors and it joins them safely; `scripts/check_twin_drift.py` in
`dhyabi2/swarm-decisions` covers the nano_sdk/nano_mcp twins and does not see
either of these.
"""

import argparse
import ast
import hashlib
import json
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "vendor"))

import nanoaddr  # noqa: E402
from canonical import checksum_pair  # noqa: E402  - one implementation, not two

TOOL = "mint"
VERSION = "mint-v1"

#: The default, and it is relative to the current working directory on purpose:
#: that is the path `autonomaavalix` named as writable in its sandbox. A default
#: under $HOME would be wrong for exactly the runtime that asked for this.
DEFAULT_KEY_NAME = "nano.key"

PRIVATE_KEY_BYTES = 32
#: A private key is 32 bytes written as hex, so the file is this many characters
#: plus whatever trailing whitespace the operator's editor adds.
KEY_FILE_HEX_LEN = PRIVATE_KEY_BYTES * 2

#: The all-zero seed at index 0, which every Nano implementation agrees on. It
#: is PUBLIC and must never hold money; it is pinned here precisely because it
#: is not a secret, and it is the runtime control in `_derivation_is_sound`.
KNOWN_VECTOR_ADDRESS = ("nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7"
                        "pwskuzi7ahz8oq6cobd99d4r3b7")

#: Exit codes. 2 is a refusal (the tool worked and the answer is no), 3 is the
#: filesystem saying no, 64 is the caller holding the tool wrong. Distinct so a
#: wrapper can branch without parsing text.
EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_IO = 3
EXIT_USAGE = 64


class Refusal(Exception):
    """The tool worked and the answer is no. `code` is stable; switch on it.

    The message is for a human and MUST NOT carry key material - see the
    module docstring. Every raise site in this file passes a path, a length or
    a reason code, never the bytes.
    """

    def __init__(self, code, detail, **extra):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.extra = extra


class IOFailure(Exception):
    """The filesystem said no, or the self-check did. Exit 3."""

    def __init__(self, code, detail, **extra):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.extra = extra


# --------------------------------------------------------------------------
# Ed25519 group arithmetic over the BLAKE2b hash - public-key derivation only.
#
# Curve constants are Ed25519's, unmodified; the ONLY difference from RFC 8032
# is which hash expands the private key, which is what makes this Nano. The
# point arithmetic is extended coordinates (X, Y, Z, T) so that a derivation
# costs one modular inversion instead of 254.
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_BASE_Y = (4 * pow(5, _P - 2, _P)) % _P


def _recover_x(y, x_is_odd):
    """The x matching this y on the curve, or None if there is none.

    Returns None rather than guessing for a y that is not on the curve at all,
    which is what makes a corrupted point an error instead of a wrong answer.
    """
    y_squared = y * y % _P
    numerator = (y_squared - 1) % _P
    denominator = (_D * y_squared + 1) % _P
    x_squared = numerator * pow(denominator, _P - 2, _P) % _P
    if x_squared == 0:
        return 0 if not x_is_odd else None
    x = pow(x_squared, (_P + 3) // 8, _P)
    if x * x % _P != x_squared:
        x = x * _SQRT_M1 % _P
    if x * x % _P != x_squared:
        return None
    if bool(x & 1) != bool(x_is_odd):
        x = _P - x
    return x


_BASE_POINT = None


def _base_point():
    global _BASE_POINT
    if _BASE_POINT is None:
        x = _recover_x(_BASE_Y, False)
        if x is None:  # pragma: no cover - the curve constants are fixed
            raise IOFailure("curve_constants_broken",
                            "the Ed25519 base point does not lie on the curve")
        _BASE_POINT = (x, _BASE_Y, 1, x * _BASE_Y % _P)
    return _BASE_POINT


def _point_add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(scalar):
    """`scalar` times the base point, as an extended-coordinate point."""
    result = (0, 1, 1, 0)
    point = _base_point()
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _compress(point):
    """The 32-byte little-endian encoding of a point: y, with x's sign on top."""
    x, y, z, _ = point
    z_inverse = pow(z, _P - 2, _P)
    x = x * z_inverse % _P
    y = y * z_inverse % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _clamp(scalar_bytes):
    """RFC 8032's clamping: clear the low 3 bits, clear bit 255, set bit 254.

    Clearing the low bits puts the scalar in the prime-order subgroup; setting
    bit 254 fixes its length so the multiply is not variable-time in the key.
    """
    scalar = int.from_bytes(scalar_bytes, "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar


def public_key_for(private_key, hasher=None):
    """The 32-byte Nano public key for a 32-byte private key.

    `hasher` exists for ONE reason: handed `hashlib.sha512` this function is
    standard Ed25519 and can be held against RFC 8032's published vectors
    (test 21). Production never passes it. Nothing else in this repository may
    call it with an argument.
    """
    if not isinstance(private_key, (bytes, bytearray)):
        raise Refusal("key_file_malformed",
                      "a private key must be %d bytes" % PRIVATE_KEY_BYTES)
    if len(private_key) != PRIVATE_KEY_BYTES:
        # The length, never the content: see the module docstring.
        raise Refusal("key_file_malformed",
                      "a private key must be %d bytes, got %d"
                      % (PRIVATE_KEY_BYTES, len(private_key)))
    if hasher is None:
        expanded = hashlib.blake2b(bytes(private_key), digest_size=64).digest()
    else:
        expanded = hasher(bytes(private_key)).digest()
    return _compress(_scalar_mult(_clamp(expanded[:32])))


def address_for(private_key, prefix="nano_"):
    """The checksummed account address a private key controls."""
    return nanoaddr.encode(public_key_for(private_key), prefix)


def _derivation_is_sound():
    """Re-derive the known public account, at mint time, every time.

    THE GAP THIS CLOSES, which is worth stating plainly because the obvious
    self-check does not close it. Round-tripping a minted address through
    `nanoaddr.decode` proves the ADDRESS ENCODING is consistent; it says
    nothing about whether the private key controls that public key, because
    both halves of the round trip read the same `_scalar_mult`. A derivation
    that is wrong in the same way twice passes it, and the operator publishes
    an address whose key nobody holds - payments to it are unspendable, which
    is the `nano-mcp-public` defect over again from the other end.

    Tests 21 and 22 hold the derivation against RFC 8032 and against this
    vector, but a test is a BUILD-time guarantee. It is not present when a
    patched `nanoaddr`, a corrupted install or a half-written file is what
    actually runs, and that is exactly the case where the money is lost. So
    the vector is re-derived on every mint: one scalar multiplication,
    deterministic, no network, no secret involved.

    It cannot prove the derivation correct for all inputs - only that this
    build still reproduces a value it could not reach by accident. That is the
    strongest runtime check available without implementing signatures, which
    this file deliberately does not do.
    """
    private_key = hashlib.blake2b(
        bytes(32) + (0).to_bytes(4, "big"), digest_size=32).digest()
    return nanoaddr.encode(public_key_for(private_key), "nano_") == \
        KNOWN_VECTOR_ADDRESS


# --------------------------------------------------------------------------
# the key file
# --------------------------------------------------------------------------

def _new_private_key():
    """32 bytes from the operating system's CSPRNG, and nothing else.

    `os.urandom` only. No `random`, no clock, no pid, no mixing: a mix with a
    weak source is not stronger than the strong source alone, and every line of
    mixing is a line that can silently reduce the entropy. Test 7 asserts this
    module never imports `random`, test 8 that it never reads the clock, and
    test 9 that two mints differ - which any deterministic seeding fails.
    """
    return os.urandom(PRIVATE_KEY_BYTES)


def _read_private_key(path):
    """The private key in `path`, or raise. Never echoes the content."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        raise Refusal("key_file_missing",
                      "no key file at %s - run `mint.py new` first" % path) from None
    except OSError as exc:
        raise IOFailure("key_file_unreadable",
                        "cannot read %s: %s" % (path, exc.strerror)) from None
    candidate = text.strip()
    if len(candidate) != KEY_FILE_HEX_LEN:
        raise Refusal(
            "key_file_malformed",
            "%s holds %d characters; a private key is %d hex characters. "
            "Its content is not shown here on purpose."
            % (path, len(candidate), KEY_FILE_HEX_LEN))
    try:
        return bytes.fromhex(candidate)
    except ValueError:
        raise Refusal(
            "key_file_malformed",
            "%s is the right length but is not hexadecimal. Its content is "
            "not shown here on purpose." % path) from None


def _write_key_atomically(path, private_key):
    """Write the key at mode 0600, atomically, or raise IOFailure.

    The mode is set by `mkstemp`, which opens with O_CREAT|O_EXCL at 0600 - so
    the file has never, at any instant, been readable by anyone else. Writing
    then chmod-ing would leave a window at the umask's mode, which on a shared
    runner is the whole account. `os.replace` is atomic within one filesystem,
    so a reader sees either no file or the finished one, and the temporary lives
    in the TARGET directory because a cross-device replace is not atomic.

    Test 12 wraps `os.open` and asserts no creating call used a looser mode.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        raise IOFailure(
            "path_not_writable",
            "%s is not a directory, so no key file can be written there. Pass "
            "--host-path <dir> to choose a directory you control." % directory)
    try:
        handle, temporary = tempfile.mkstemp(dir=directory, prefix=".nano-key-")
    except OSError as exc:
        raise IOFailure(
            "path_not_writable",
            "cannot create a file in %s (%s). An ephemeral or read-only "
            "workspace needs an explicit directory: pass --host-path <dir> "
            "with a path you control." % (directory, exc.strerror)) from None
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(private_key.hex() + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError as exc:
        _remove_quietly(temporary)
        raise IOFailure(
            "path_not_writable",
            "cannot write %s (%s). Pass --host-path <dir> with a directory you "
            "control." % (path, exc.strerror)) from None


def _remove_quietly(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _mode_of(path):
    return "0%o" % stat.S_IMODE(os.stat(path).st_mode)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def mint(path, prefix_only=False):
    """Create one keypair, store the secret, return the public half.

    The order is load-bearing. The key is derived and SELF-CHECKED before the
    response is built, and if the round trip fails the file is removed: a mint
    that cannot prove its own address is worse than no mint, because the
    operator would publish an address and wait forever for a payment that
    cannot arrive.
    """
    target = os.path.abspath(path)
    if os.path.exists(target):
        # Name the account that is already there, so an operator who ran this
        # twice can see it is the same one and has lost nothing - and name it
        # WITHOUT the secret. A `--force` flag would make this refusal
        # optional, which is the same as not having it.
        existing = None
        try:
            existing = address_for(_read_private_key(target))
        except (Refusal, IOFailure):
            existing = None
        raise Refusal(
            "key_file_exists",
            "%s already exists and this tool never overwrites a key file: "
            "overwriting it would destroy the only copy of that account. "
            "Choose another --path, or move the existing file yourself."
            % target,
            existing_address=existing,
            existing_address_unreadable=existing is None)

    # Before anything is generated or written: if this build cannot reproduce
    # the known account, nothing it derives can be trusted, and the right
    # answer is to refuse while the filesystem is still untouched.
    try:
        sound = _derivation_is_sound()
    except Exception:
        sound = False
    if not sound:
        raise IOFailure(
            "derivation_unsound",
            "this build does not reproduce the known all-zero-seed account, so "
            "its key derivation cannot be trusted and no key was created. "
            "Nothing was written. Check out a clean copy of mint.py and "
            "vendor/nanoaddr.py and run `mint.py --self-test`.")

    private_key = _new_private_key()
    _write_key_atomically(target, private_key)

    try:
        address = address_for(private_key)
        if nanoaddr.decode(address) != public_key_for(private_key):
            raise nanoaddr.InvalidAddress("round_trip", "decode did not invert encode")
    except Exception:
        # Anything at all: a bad codec, a patched one, a broken curve constant.
        # The file goes, so a bad mint never leaves a key behind whose address
        # nobody can derive. The original exception is deliberately NOT chained
        # or re-raised - its message may carry key material.
        _remove_quietly(target)
        raise IOFailure(
            "self_check_failed",
            "the derived address did not survive a decode/encode round trip, "
            "so it is not usable; the key file at %s has been removed. Nothing "
            "about the key is printed." % target) from None

    response = {
        "v": VERSION,
        "address_prefix": address[:9],
        "checksum_ok": True,
        "stored_at": target,
        "mode": _mode_of(target),
        "entropy_source": "os.urandom",
        "secret_in_this_output": False,
        "network_calls_made": 0,
        "back_up_this_one_file": target,
        "cannot_be_automated_from_here":
            "backing up that file is yours; losing it loses the account",
    }
    if not prefix_only:
        response["address"] = address
    return response


def address_of(path, prefix_only=False):
    """The public address behind a key file. Never the secret."""
    address = address_for(_read_private_key(os.path.abspath(path)))
    document = {
        "v": VERSION,
        "address_prefix": address[:9],
        "stored_at": os.path.abspath(path),
        "secret_in_this_output": False,
    }
    if not prefix_only:
        document["address"] = address
    return document


def check_address(address):
    """The eddie_researcher repair: is this address real, and if not, why.

    `nanoaddr.validate` decides, and `canonical.checksum_pair` supplies the two
    halves for the message - the SAME function `http_claim.py`'s
    `/check-address` reads, so the two surfaces cannot give one address two
    expected checksums. Test 18 holds them together over twelve addresses.
    """
    verdict = nanoaddr.validate(address)
    carried, implied = checksum_pair(address)
    if verdict["valid"]:
        return {
            "v": VERSION,
            "address": verdict["normalised"],
            "checksum_ok": True,
            "public_key_halves": [verdict["public_key"][:32], verdict["public_key"][32:]],
            "prefix_given": verdict["prefix"],
            "this_address_would_lose_the_payment": False,
            "note": "Checksum matches. A payment to this address arrives.",
        }
    document = {
        "v": VERSION,
        "address": address.strip() if isinstance(address, str) else address,
        "checksum_ok": False,
        "reason": verdict["reason"],
        "message": verdict["message"],
        "this_address_would_lose_the_payment": True,
        "fix": "the last 8 characters encode the checksum; recompute them over "
               "the 32-byte public key with blake2b-40 (blake2b digest_size=5, "
               "digest reversed, base32 in Nano's alphabet)",
    }
    if verdict["reason"] == "bad_checksum":
        document["expected_checksum"] = implied
        document["given_checksum"] = carried
    return document


# --------------------------------------------------------------------------
# --self-test
# --------------------------------------------------------------------------

def self_test():
    """Run the controls in a temporary directory and report. No network.

    Reports the negative controls BY REASON CODE, because a count of refusals
    that does not say which reason fired cannot tell "refused for the right
    reason" from "refused because the tool is broken".
    """
    controls = []

    def negative(name, expected, call):
        try:
            call()
        except (Refusal, IOFailure) as exc:
            controls.append({"control": name, "expected": expected,
                             "got": exc.code, "ok": exc.code == expected})
        except Exception as exc:  # pragma: no cover - a bug, reported not raised
            controls.append({"control": name, "expected": expected,
                             "got": type(exc).__name__, "ok": False})
        else:
            controls.append({"control": name, "expected": expected,
                             "got": "no refusal", "ok": False})

    with tempfile.TemporaryDirectory() as scratch:
        key = os.path.join(scratch, DEFAULT_KEY_NAME)
        first = mint(key)
        positives = [
            {"control": "a mint stores a 0600 file",
             "ok": _mode_of(key) == "0600"},
            {"control": "the address round-trips through the codec",
             "ok": nanoaddr.is_valid(first["address"])},
            {"control": "the response carries no secret",
             "ok": _read_private_key(key).hex() not in json.dumps(first)},
            {"control": "two mints are two accounts",
             "ok": mint(os.path.join(scratch, "second.key"))["address"]
                   != first["address"]},
            {"control": "RFC 8032 vector 1 (this derivation under sha512)",
             "ok": public_key_for(
                 bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                               "4449c5697b326919703bac031cae7f60"),
                 hashlib.sha512).hex()
                 == "d75a980182b10ab7d54bfed3c964073a"
                    "0ee172f3daa62325af021a68f707511a"},
            {"control": "the known zero-seed account derives",
             "ok": address_for(hashlib.blake2b(
                 bytes(32) + (0).to_bytes(4, "big"), digest_size=32).digest())
                 == "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7"
                    "pwskuzi7ahz8oq6cobd99d4r3b7"},
        ]
        negative("minting onto an existing file", "key_file_exists",
                 lambda: mint(key))
        negative("reading a key file that is not there", "key_file_missing",
                 lambda: address_of(os.path.join(scratch, "absent.key")))
        short = os.path.join(scratch, "short.key")
        with open(short, "w", encoding="utf-8") as handle:
            handle.write("ab" * 20 + "\n")
        negative("a key file of the wrong length", "key_file_malformed",
                 lambda: address_of(short))
        nonhex = os.path.join(scratch, "nonhex.key")
        with open(nonhex, "w", encoding="utf-8") as handle:
            handle.write("z" * KEY_FILE_HEX_LEN + "\n")
        negative("a key file that is not hexadecimal", "key_file_malformed",
                 lambda: address_of(nonhex))
        negative("a private key of the wrong size", "key_file_malformed",
                 lambda: public_key_for(b"\x01" * 31))
        negative("a private key that is not bytes", "key_file_malformed",
                 lambda: public_key_for("not bytes"))
        negative("writing into a path that is not a directory",
                 "path_not_writable",
                 lambda: mint(os.path.join(key, "under-a-file.key")))
        negative("writing into a directory that does not exist",
                 "path_not_writable",
                 lambda: mint(os.path.join(scratch, "absent-dir", "k.key")))

    broken = check_address(
        "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b8")
    positives.append({"control": "a one-character typo is caught",
                      "ok": broken["checksum_ok"] is False
                            and broken.get("expected_checksum") is not None})

    checks = positives + controls
    return {
        "tool": TOOL,
        "v": VERSION,
        "ok": all(check["ok"] for check in checks),
        "network_calls_made": 0,
        "negative_controls": len(controls),
        "negative_controls_refused_on_their_own_reason":
            sum(1 for check in controls if check["ok"]),
        "checks": checks,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def imports_of(path=None):
    """The top-level module names `mint.py` imports, from its AST.

    Here rather than only in the test so that `--self-test`'s claim of
    `network_calls_made: 0` is checkable by the same means a reader would use.
    """
    target = path or os.path.abspath(__file__)
    with open(target, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def _emit(document, out):
    out.write(json.dumps(document, sort_keys=True, indent=2) + "\n")


def main(argv=None, out=None, err=None):
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    parser = argparse.ArgumentParser(
        prog="mint.py",
        description="Mint one Nano keypair from this machine's own entropy. "
                    "The secret is written to one file at mode 0600 and is "
                    "never printed. No network, ever.")
    parser.add_argument("--self-test", action="store_true",
                        help="run the controls in a temporary directory, exit 0 "
                             "only if all pass")
    sub = parser.add_subparsers(dest="command")

    new = sub.add_parser("new", help="create one keypair")
    new.add_argument("--path", help="where to store the secret "
                                    "(default ./%s)" % DEFAULT_KEY_NAME)
    new.add_argument("--host-path", help="a directory you control; the key is "
                                         "written to <dir>/%s. For ephemeral "
                                         "or read-only workspaces."
                                         % DEFAULT_KEY_NAME)
    new.add_argument("--print-prefix-only", action="store_true",
                     help="emit only the first 9 characters of the address")

    show = sub.add_parser("address", help="the address behind a key file")
    show.add_argument("--path", required=True)
    show.add_argument("--prefix-only", action="store_true")

    check = sub.add_parser("check", help="is this address real")
    check.add_argument("--address", required=True)

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 on a bad flag; this tool's 2 means "refused", so a
        # usage error is translated to 64 and cannot be confused with a verdict.
        return EXIT_USAGE if exc.code else EXIT_OK

    if args.self_test:
        report = self_test()
        _emit(report, out)
        return EXIT_OK if report["ok"] else EXIT_IO
    if args.command is None:
        parser.print_help(err)
        return EXIT_USAGE

    try:
        if args.command == "new":
            if args.path and args.host_path:
                print("mint.py: pass --path or --host-path, not both: they name "
                      "the same thing two ways.", file=err)
                return EXIT_USAGE
            if args.host_path:
                path = os.path.join(args.host_path, DEFAULT_KEY_NAME)
            else:
                path = args.path or DEFAULT_KEY_NAME
            _emit(mint(path, prefix_only=args.print_prefix_only), out)
            return EXIT_OK
        if args.command == "address":
            _emit(address_of(args.path, prefix_only=args.prefix_only), out)
            return EXIT_OK
        verdict = check_address(args.address)
        _emit(verdict, out)
        return EXIT_OK if verdict["checksum_ok"] else EXIT_REFUSED
    except Refusal as exc:
        document = {"tool": TOOL, "v": VERSION, "error": exc.code,
                    "reason": exc.code, "detail": exc.detail,
                    "secret_in_this_output": False}
        document.update(exc.extra)
        _emit(document, out)
        return EXIT_REFUSED
    except IOFailure as exc:
        document = {"tool": TOOL, "v": VERSION, "error": exc.code,
                    "reason": exc.code, "detail": exc.detail,
                    "secret_in_this_output": False}
        document.update(exc.extra)
        _emit(document, out)
        return EXIT_IO


if __name__ == "__main__":
    sys.exit(main())
