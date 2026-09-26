"""Exact XNO <-> raw conversion. Integers only; no float touches money.

1 XNO = 10**30 raw. A float carries ~15-17 significant digits, so a single
float anywhere in this path silently loses the bottom 13+ digits of every
amount. Both functions below are copied verbatim from
`tools/nano_wallet/wallet.py` in dhyabi2/swarm-decisions, which is the
source of truth for them; they are vendored here so this repository has no
dependency of any kind, including on that one.
"""

RAW_PER_XNO = 10 ** 30


def xno_to_raw(amount: str) -> int:
    """Exact decimal XNO -> integer raw. No float is used anywhere."""
    text = str(amount).strip()
    if not text:
        raise ValueError("amount is empty")
    negative = text.startswith("-")
    if negative:
        raise ValueError("amount must not be negative")
    if text.count(".") > 1:
        raise ValueError("amount is not a decimal number: %r" % amount)
    whole, _, frac = text.partition(".")
    whole = whole or "0"
    if not whole.isdigit() or (frac and not frac.isdigit()):
        raise ValueError("amount is not a decimal number: %r" % amount)
    if len(frac) > 30:
        raise ValueError("Nano has 30 decimal places; %d were given" % len(frac))
    return int(whole) * RAW_PER_XNO + int(frac.ljust(30, "0") or 0)


def raw_to_xno(raw: int) -> str:
    """Integer raw -> exact decimal XNO string, no trailing-zero noise."""
    if not isinstance(raw, int):
        raise ValueError("raw must be an integer, got %s" % type(raw).__name__)
    if raw < 0:
        raise ValueError("raw must not be negative")
    whole, frac = divmod(raw, RAW_PER_XNO)
    if frac == 0:
        return str(whole)
    return "%d.%s" % (whole, str(frac).zfill(30).rstrip("0"))
