"""The one module in this repository allowed to open a socket.

Everything else - `settle.py` included - talks to the chain through the
`NanoNode` interface below, so "what can reach the network" is answerable by
reading one file. `tests/test_settle.py` asserts that: it walks the import graph
and fails the build if any other module reachable from `settle.py` imports
`socket`, `http` or `urllib`.

Only one RPC is implemented, `block_info`, because recording a payment needs
exactly one question answered: is this block confirmed, and what did it move to
whom. Nothing here can send, sign, or unlock anything.
"""

import json
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 15


class NodeError(Exception):
    """The node could not be reached, or did not answer with JSON."""


class NanoNode:
    """The interface `settle.py` depends on.

    One method. A real node and a fixture are interchangeable, which is why
    every test runs against `FakeNode` and none opens a socket.
    """

    def block_info(self, block_hash: str) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class HttpNanoNode(NanoNode):
    """A public Nano node over HTTP. Read-only by construction."""

    def __init__(self, url: str, timeout: int = DEFAULT_TIMEOUT):
        self.url = url
        self.timeout = timeout

    def block_info(self, block_hash: str) -> dict:
        payload = json.dumps({
            "action": "block_info",
            "json_block": "true",
            "hash": block_hash,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise NodeError("HTTP %s" % exc.code) from None
        except urllib.error.URLError as exc:
            raise NodeError(str(exc.reason)) from None
        except OSError as exc:
            raise NodeError(str(exc)) from None
        try:
            document = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise NodeError("the response was not JSON") from None
        if not isinstance(document, dict):
            raise NodeError("the response was not a JSON object")
        return document


class FakeNode(NanoNode):
    """A node fixture. `responses` maps an uppercase block hash to a dict.

    A hash that is not in the map answers the way a real node answers for a
    block it has never seen, so the "block not found" path is exercised by
    absence rather than by a special case.
    """

    NOT_FOUND = {"error": "Block not found"}

    def __init__(self, responses=None, raises=None):
        self.responses = dict(responses or {})
        self.raises = raises
        self.calls = []

    def block_info(self, block_hash: str) -> dict:
        self.calls.append(block_hash)
        if self.raises is not None:
            raise NodeError(self.raises)
        return dict(self.responses.get(block_hash.upper(), self.NOT_FOUND))
