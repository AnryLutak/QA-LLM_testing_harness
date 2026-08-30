from dataclasses import dataclass, field
import os
import re

@dataclass
class Money:
    values: set = field(default_factory=set)
    unparseable: list = field(default_factory=list)

CURRENCY = r"(?:€|eur(?:os?)?\b)"
SPACES    = "\u0020\u00a0\u202f"          # space, no-break, narrow no-break
# The trailing [kKmM] matters: without it "1.4k EUR" is not DETECTED at
# all, so it returns as "no money" rather than as an unreadable amount —
# the fail-open bug this module exists to prevent, one layer further out.
# The detector must be loose enough to notice everything money-shaped,
# including shapes the parser will refuse.
NUM_LOOSE = rf"\d[\d.,{SPACES}]*\d[kKmM]?|\d[kKmM]?"    # LOOSE: any digit-led run

DETECT = re.compile(
    rf"{CURRENCY}\s*(?P<a>{NUM_LOOSE})|(?P<b>{NUM_LOOSE})\s*{CURRENCY}",
    re.IGNORECASE,
)

# A thousands separator is a dot, a comma, or a space (plain / no-break /
# narrow no-break) followed by EXACTLY three digits. The rule is about the
# group length, not the symbol, which is why the same expression covers
# "1.400", "1,400" and "1 400" without any locale detection.
_SEP = "[.,\u0020\u00a0\u202f]"
STRICT = re.compile("^\\d{1,3}(?:" + _SEP + "\\d{3})+$|^\\d+$")

# The parser as it was before it learned separators: digits only, nothing
# else. Reachable via HARNESS_BUGS=money_parser_naive, which is how the
# ERROR path gets demonstrated end to end WITHOUT leaving a real check
# broken. Same idea as BUGS= in agent/agent.py: a seeded, labelled, opt-in
# defect beats a genuine one kept around for the screenshot.
NAIVE = re.compile(r"^\d{3,5}$")

def harness_bugs():
    """Seeded HARNESS defects, READ AT CALL TIME.

    This was `HARNESS_BUGS = {...}` at module scope, and it was the last knob
    in the repo still frozen at import — the same defect agent.bugs(),
    noise.temp(), llm.temperature() and knowledge's `_ensure` each document
    from their own side, and the one `test_every_agent_knob_is_read_at_call_time`
    pins for agent/ but cannot see here:

        >>> from evals.extract import money_mentions   # anything imports it
        >>> os.environ["HARNESS_BUGS"] = "money_parser_naive"
        >>> money_mentions("1 400 EUR").values
        {1400}

    — the seeded defect never arms, Status.ERROR stays unreachable, and the
    coverage claim in agent/noise.py's _MONEY_STYLES comment goes stale again
    with nothing to announce it. It is also why
    test_seeded_naive_parser_makes_ERROR_reachable had to spawn a SUBPROCESS to
    observe its own switch: exactly the deferred-import gymnastics evals/redteam.py
    carried until agent/ stopped reading its environment at import.

    The module-level `HARNESS_BUGS` name is GONE rather than kept alongside
    this function. A snapshot left in place for compatibility is a snapshot the
    next reader will use, which reintroduces the freeze one import away.
    """
    return {b.strip() for b in os.environ.get("HARNESS_BUGS", "").split(",")
            if b.strip()}

# A CEILING, AND DELIBERATELY NO FLOOR.
#
# The ceiling refuses a magnitude the parser has probably MIS-READ rather than
# returning it: "€12345678" is money-shaped, and reading it as 12.3M EUR/month
# is not a parse, it is a mis-grouped separator. That refusal is fail-closed and
# is pinned by the implausibly-long-number row in tests/test_extract.py.
#
# There used to be a floor at 100, and a floor is not the same kind of guard.
# "50 EUR" is not a mis-read, it is fifty euros — the detector already required
# a currency token beside it. Refusing it sent a perfectly readable figure to
# .unparseable, and check_grounding then reported Status.ERROR: "the harness
# cannot read this, go fix the parser", for an answer that had quoted a number
# no document supports. That is Status.FAIL and somebody else's ticket. Both
# block the build, so it never went green — it went to the wrong engineer,
# which is the exact misattribution check_forbidden's comment argues against one
# module up.
MAX_PLAUSIBLE = 999_999

def _parse(raw):
    """One span -> int, or None if this parser will not guess."""
    candidate = raw.strip()
    pattern = NAIVE if "money_parser_naive" in harness_bugs() else STRICT
    if not pattern.match(candidate):
        return None
    value = int(re.sub(_SEP, "", candidate))
    if value > MAX_PLAUSIBLE:
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