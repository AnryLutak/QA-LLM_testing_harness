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


@dataclass
class Result:
    name: str
    stage: str          # routing | retrieval | tool_call | generation
    passed: bool
    detail: str = ""
    meta: dict = field(default_factory=dict)


def check_intent(trace, expected):
    got = (trace.get("routing") or {}).get("intent")
    return Result(
        name="intent", stage="routing", passed=got == expected,
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
        name="retrieval", stage="retrieval", passed=not missing and not extra,
        detail=detail,
        meta={"precision": round(precision, 3), "recall": round(recall, 3),
              "missing": missing, "extra": extra},
    )


def check_tools(trace, expected_names):
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
        name="tool_calls", stage="tool_call", passed=not missing and not extra,
        detail=detail, meta={"expected": sorted(exp_set), "actual": sorted(got_set)},
    )


def check_forbidden(text, forbidden):
    """Substrings that must never appear — the cheapest hallucination guard.

    Not a general solution, but for a known failure mode ("quotes a price that
    exists in no document") an exact string check is faster, cheaper and more
    reliable than asking a model whether the answer was grounded.
    """
    # Boundary-aware. Plain substring matching flagged the legitimate "1400 EUR"
    # as containing the forbidden "400 EUR" - a false positive that would have
    # had someone debugging a hallucination that never happened.
    import re as _re
    hits = []
    for f in (forbidden or []):
        pattern = r"(?<![\w.])" + _re.escape(f) + r"(?![\w.])"
        if _re.search(pattern, text, _re.IGNORECASE):
            hits.append(f)
    return Result(
        name="forbidden_content", stage="generation", passed=not hits,
        detail=f"found {hits}" if hits else "none present",
        meta={"hits": hits},
    )


def check_grounding(text, trace):
    """Every EUR figure in the answer must come from a retrieved document.

    This is the assertion that catches the hallucinated-price bug without a
    judge. Cheap, exact, and it fails with a specific number you can point at.
    """
    import re
    from agent import knowledge

    currency = r"(?:€|EURO?|euros?)"
    amount = r"(\d{1,3}(?:,\d{3})+|\d{3,5})"

    before = re.findall(rf"{currency}\s*{amount}", text, re.IGNORECASE)
    after = re.findall(rf"{amount}\s*{currency}", text, re.IGNORECASE)

    quoted = {
        int(x.replace(",", ""))
        for x in before + after
    }
    if not quoted:
        return Result(name="grounding", stage="generation", passed=True,
                      detail="no figures quoted")

    retrieved = (trace.get("retrieval") or {}).get("doc_ids", [])
    allowed = {knowledge.get(i)["price"] for i in retrieved
               if knowledge.get(i) and "price" in knowledge.get(i)}

    # An average computed by a tool is legitimate even though it appears in no document.
    for call in (trace.get("tool_call") or {}).get("calls", []):
        if isinstance(call.get("result"), (int, float)):
            allowed.add(int(call["result"]))

    ungrounded = sorted(quoted - allowed)
    return Result(
        name="grounding", stage="generation", passed=not ungrounded,
        detail=(f"figures not in any retrieved doc: {ungrounded}" if ungrounded
                else f"all {len(quoted)} figures grounded"),
        meta={"quoted": sorted(quoted), "allowed": sorted(allowed), "ungrounded": ungrounded},
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
        name="tool_results", stage="tool_call", passed=not problems,
        detail="; ".join(problems) if problems else "tool outputs match recomputation",
        meta={"problems": problems},
    )


def run_all(case, text, trace):
    exp = case["expect"]
    results = [
        check_intent(trace, exp["intent"]),
        check_retrieval(trace, exp.get("doc_ids", [])),
        check_tools(trace, exp.get("tools", [])),
        check_tool_results(trace),
        check_forbidden(text, exp.get("must_not_contain")),
        check_grounding(text, trace),
    ]
    return results
