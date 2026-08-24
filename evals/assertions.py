"""Deterministic checks.

Everything here is exact. No model, no judgement, no flakiness. Anything that
*can* be asserted should be — asserting is free, repeatable and explains itself,
whereas judging costs money, varies between runs and produces a number you then
have to interpret.

Each check returns a Result carrying the stage it belongs to, so the runner can
attribute a failure to the earliest broken stage rather than reporting only
that the final answer was wrong.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    """The four conclusions a check can reach.

    Defined HERE and not in runner.py. A check's status is part of the
    vocabulary a check speaks; the runner is a consumer of that vocabulary.
    Putting Status in the runner forces assertions to import their own
    consumer — a circular import, and backwards layering even if Python
    happened to tolerate it.

    What does belong in the runner is BLOCKING: the policy that collapses
    these four into a build decision. Vocabulary here, policy there.
    """

    PASS = "pass"
    FAIL = "fail"
    NA = "n/a"        # nothing to check — legitimately vacuous
    ERROR = "error"   # could not evaluate. Harness bug, not agent bug.


@dataclass
class Result:
    name: str
    stage: str          # routing | retrieval | tool_call | generation
    status: Status
    detail: str = ""
    meta: dict = field(default_factory=dict)

# DECLARED-EMPTY IS NOT UNDECLARED, AND `.get(key, [])` CANNOT TELL THEM APART.
#
# `expect.doc_ids: []` says "this query must retrieve nothing" — a real
# assertion, and one several chitchat cases depend on. A missing `doc_ids` key
# says the dataset never stated an expectation. Collapsing both to `[]` made the
# second one PASS: an empty expectation compared against an empty result is an
# "exact match".
#
# That is the fail-open bug this module was rewritten to eliminate, surviving in
# the one place nobody looked — the arguments, not the checks. It also made
# VACUOUS unreachable: check_intent could never return N/A, so `outcome()` could
# never see an all-N/A case and the report printed `VACUOUS: 0` unconditionally.
# A verdict that cannot occur reads exactly like a verdict that never occurs.
#
# So: None means undeclared and yields N/A. Every check below takes its
# expectation as `exp.get(key)` with no default — see run_all.
def _undeclared(name, stage, key):
    return Result(
        name=name, stage=stage, status=Status.NA,
        detail=f"dataset declares no {key!r} for this case — nothing to check",
        meta={},
    )


def check_intent(trace, expected):
    if expected is None:
        return _undeclared("intent", "routing", "intent")
    got = (trace.get("routing") or {}).get("intent")
    return Result(
        name="intent", stage="routing", status=Status.PASS if got == expected else Status.FAIL,
        detail=f"expected {expected!r}, got {got!r}",
        meta={"expected": expected, "actual": got},
    )


def check_retrieval(trace, expected_ids):
    """Set comparison, plus precision and recall.

    Reported separately on purpose. Missing a document and returning extra
    documents are different bugs with different causes: the first is usually a
    filter or an embedding problem, the second is usually a threshold that is
    too loose. Collapsing them into one pass/fail hides which one you have.
    """
    if expected_ids is None:
        return _undeclared("retrieval", "retrieval", "doc_ids")
    got = (trace.get("retrieval") or {}).get("doc_ids", [])
    exp_set, got_set = set(expected_ids), set(got)

    missing = sorted(exp_set - got_set)
    extra = sorted(got_set - exp_set)

    precision = len(exp_set & got_set) / len(got_set) if got_set else (1.0 if not exp_set else 0.0)
    recall = len(exp_set & got_set) / len(exp_set) if exp_set else 1.0

    detail = "exact match"
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing {missing}")
        if extra:
            parts.append(f"unexpected {extra}")
        detail = "; ".join(parts)

    return Result(
        name="retrieval", stage="retrieval", 
        status=Status.PASS if not missing and not extra else Status.FAIL,
        detail=detail,
        meta={"precision": round(precision, 3), "recall": round(recall, 3),
              "missing": missing, "extra": extra},
    )


def check_tools(trace, expected_names):
    if expected_names is None:
        return _undeclared("tool_calls", "tool_call", "tools")
    got = (trace.get("tool_call") or {}).get("names", [])
    exp_set, got_set = set(expected_names), set(got)
    missing = sorted(exp_set - got_set)
    extra = sorted(got_set - exp_set)

    detail = "exact match"
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"not called {missing}")
        if extra:
            parts.append(f"unexpectedly called {extra}")
        detail = "; ".join(parts)

    return Result(
        name="tool_calls", stage="tool_call", 
        status=Status.PASS if not missing and not extra else Status.FAIL,
        detail=detail, meta={"expected": sorted(exp_set), "actual": sorted(got_set)},
    )


def check_forbidden(text, forbidden=None, forbidden_amounts=None):
    """Content that must never appear. Two kinds, checked differently.

    STRINGS (`must_not_contain`) are for non-money phrases — "I found",
    "viewing request". Boundary-aware substring matching is right for these.

    AMOUNTS (`must_not_contain_amounts`) are for money, and they are compared
    as normalised integers via money_mentions(). That makes them immune to
    formatting: 400 catches "400 EUR", "€400", "400 euros" and "EUR 400"
    alike. The string form could only ever catch the spelling it was written
    in, which is how a reworded answer walked past this check.
    """
    import re as _re
    from evals.extract import money_mentions

    forbidden = forbidden or []
    forbidden_amounts = set(forbidden_amounts or [])

    # Neither kind defined means there is nothing to check. NOT a pass.
    if not forbidden and not forbidden_amounts:
        return Result(
            name="forbidden_content", stage="generation", status=Status.NA,
            detail="no must_not_contain or must_not_contain_amounts for this case",
            meta={"hits": [], "amount_hits": []},
        )

    # Boundary-aware. Plain substring matching flagged the legitimate "1400 EUR"
    # as containing the forbidden "400 EUR" - a false positive that would have
    # had someone debugging a hallucination that never happened.
    hits = []
    for f in forbidden:
        pattern = r"(?<![\w.])" + _re.escape(f) + r"(?![\w.])"
        if _re.search(pattern, text, _re.IGNORECASE):
            hits.append(f)

    amount_hits, unparseable = [], []
    if forbidden_amounts:
        money = money_mentions(text)
        unparseable = money.unparseable
        amount_hits = sorted(forbidden_amounts & money.values)

    # A CONFIRMED VIOLATION OUTRANKS AN INCONCLUSIVE ONE.
    #
    # This used to return ERROR the moment any money was unreadable, before
    # looking at `hits` — so a forbidden STRING that had already been found in
    # the answer was thrown away and the observation was filed as a harness
    # defect. Both block the build, so nothing went green; what went wrong is
    # attribution. ERROR says "go fix your parser", FAIL says "the agent said
    # something it must not", and printing the first when the second is known
    # sends someone to the wrong repository with the wrong ticket.
    #
    # So: report the violation, and carry the unread amounts in the detail so
    # the coverage gap is still visible rather than swallowed.
    if hits or amount_hits:
        detail = f"found {hits + amount_hits}"
        if unparseable:
            detail += (f"; additionally could not parse {unparseable}, so "
                       f"{sorted(forbidden_amounts)} is not fully ruled out")
        return Result(
            name="forbidden_content", stage="generation", status=Status.FAIL,
            detail=detail,
            meta={"hits": hits, "amount_hits": amount_hits,
                  "unparseable": unparseable},
        )

    # Nothing confirmed, and money we cannot read. Fail closed, exactly as
    # check_grounding does: we cannot claim the forbidden amount is absent.
    if unparseable:
        return Result(
            name="forbidden_content", stage="generation", status=Status.ERROR,
            detail=f"cannot parse money, so cannot rule out {sorted(forbidden_amounts)}: "
                   f"{unparseable}",
            meta={"hits": hits, "amount_hits": [], "unparseable": unparseable},
        )

    return Result(
        name="forbidden_content", stage="generation", status=Status.PASS,
        detail="none present",
        meta={"hits": [], "amount_hits": [], "unparseable": []},
    )


def check_grounding(text, trace):
    """Every EUR figure in the answer must come from a retrieved document.

    This is the assertion that catches the hallucinated-price bug without a
    judge. Cheap, exact, and it fails with a specific number you can point at.
    """

    from agent import knowledge
    from evals.extract import money_mentions

    m = money_mentions(text)

    # Guard clauses: each early return is one reason to stop, read on its own.
    if m.unparseable:
        return Result(
            name="grounding", stage="generation", status=Status.ERROR,
            # Name what broke IN THE DETAIL — that is the line the report
            # prints. meta only reaches the JSON, which nobody reads first.
            detail=f"cannot parse: {m.unparseable}",
            meta={"quoted": [], "unparseable": m.unparseable, "ungrounded": []},
        )

    if not m.values:
        return Result(
            name="grounding", stage="generation", status=Status.NA,
            detail="no figures quoted",
            # NOT the whole answer text. This runs on every N/A observation —
            # 253 of them at TEMP=0.3 x 20 runs — and each would carry a full
            # answer into the JSON report for no diagnostic gain.
            meta={"quoted": [], "ungrounded": []},
        )

    retrieved = (trace.get("retrieval") or {}).get("doc_ids", [])
    allowed = {knowledge.get(i)["price"] for i in retrieved
               if knowledge.get(i) and "price" in knowledge.get(i)}

    # An average computed by a tool is legitimate even though it appears in no document.
    for call in (trace.get("tool_call") or {}).get("calls", []):
        if isinstance(call.get("result"), (int, float)):
            allowed.add(int(call["result"]))

    ungrounded = sorted(m.values - allowed)
    return Result(
        name="grounding", stage="generation",
        status=Status.PASS if not ungrounded else Status.FAIL,
        detail=(f"figures not in any retrieved doc: {ungrounded}" if ungrounded
                else f"all {len(m.values)} figures grounded"),
        meta={"quoted": sorted(m.values), "allowed": sorted(allowed), "ungrounded": ungrounded},
    )


def check_tool_results(trace):
    """Recompute what each tool should have returned, independently.

    Added after a gap was found: the suite asserted on WHICH tools were called
    but never on WHAT they returned, so a bug that truncated an average instead
    of rounding it scored 100%. Checking the call and not the result is a very
    easy blind spot to build.

    This recomputes from the retrieved documents rather than hardcoding an
    expected number per case. An independent oracle keeps working when the
    dataset changes, and it cannot drift out of sync with the fixtures.
    """
    from agent import knowledge

    calls = (trace.get("tool_call") or {}).get("calls", [])
    doc_ids = (trace.get("retrieval") or {}).get("doc_ids", [])

    # No tool calls means no tool results to recompute. Previously this
    # returned "tool outputs match recomputation" — a confident pass over an
    # empty list. Whether a tool SHOULD have been called is check_tools' job.
    if not calls:
        return Result(
            name="tool_results", stage="tool_call", status=Status.NA,
            detail="no tool calls to verify", meta={"problems": []},
        )

    problems = []

    for call in calls:
        if call["name"] == "average_price":
            prices = [knowledge.get(i)["price"] for i in doc_ids
                      if knowledge.get(i) and "price" in knowledge.get(i)]
            if not prices:
                continue
            expected = round(sum(prices) / len(prices))
            if call["result"] != expected:
                problems.append(
                    f"average_price returned {call['result']}, recomputed {expected} "
                    f"from {len(prices)} listings")

        elif call["name"] == "book_viewing":
            # The booked listing must be one that was actually retrieved.
            # Added after finding a booking fired on an EMPTY result set with
            # listing_id=None: checking that the tool ran, without checking its
            # arguments against retrieval, would have let that through.
            listing_id = call.get("args", {}).get("listing_id")
            if listing_id not in doc_ids:
                problems.append(
                    f"book_viewing booked {listing_id!r}, which is not among "
                    f"the retrieved listings {doc_ids}")

    return Result(
        name="tool_results", stage="tool_call", 
        status=Status.PASS if not problems else Status.FAIL,
        detail="; ".join(problems) if problems else "tool outputs match recomputation",
        meta={"problems": problems},
    )


def run_all(case, text, trace):
    exp = case["expect"]
    # No defaults. `.get(key)` returns None for an expectation the dataset never
    # stated, and each check turns that into N/A instead of a vacuous pass —
    # see the note above _undeclared.
    results = [
        check_intent(trace, exp.get("intent")),
        check_retrieval(trace, exp.get("doc_ids")),
        check_tools(trace, exp.get("tools")),
        check_tool_results(trace),
        check_forbidden(text,
                        exp.get("must_not_contain"),
                        exp.get("must_not_contain_amounts")),
        check_grounding(text, trace),
    ]
    return results
