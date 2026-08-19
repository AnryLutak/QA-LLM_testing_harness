from dataclasses import dataclass, field
import re

@dataclass
class Money:
    values: set = field(default_factory=set)
    unparseable: list = field(default_factory=list)

CURRENCY = r"(?:€|eur(?:os?)?\b)"
SPACES    = "\u0020\u00a0\u202f"          # space, no-break, narrow no-break
NUM_LOOSE = rf"\d[\d.,{SPACES}]*\d|\d"    # LOOSE: any digit-led run

DETECT = re.compile(
    rf"{CURRENCY}\s*(?P<a>{NUM_LOOSE})|(?P<b>{NUM_LOOSE})\s*{CURRENCY}",
    re.IGNORECASE,
)

STRICT = re.compile(r"^\d{1,3}(?:[.,]\d{3})+$|^\d+$")   # TIGHT
MIN_PLAUSIBLE, MAX_PLAUSIBLE = 100, 999_999

def _parse(raw):
    """One span -> int, or None if this parser will not guess."""
    candidate = raw.strip()
    if not STRICT.match(candidate):
        return None
    value = int(candidate.replace(".", "").replace(",", ""))
    if not (MIN_PLAUSIBLE <= value <= MAX_PLAUSIBLE):
        return None
    return value


def money_mentions(text):
    values, unparseable = set(), []
    for m in DETECT.finditer(text or ""):
        raw = m.group("a") if m.group("a") is not None else m.group("b")
        value = _parse(raw)
        if value is None:
            unparseable.append(m.group(0).strip())
        else:
            values.add(value)
    return Money(values=values, unparseable=unparseable)