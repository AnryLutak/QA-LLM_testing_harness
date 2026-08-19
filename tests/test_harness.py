"""Tests for the harness, not for the agent.

An eval suite is test code, and test code that has never been tested is just
code you trust for no reason. The question these answer is: if the agent broke,
would this suite actually notice?

Run with:  python3 -m pytest tests/ -v
"""

import importlib
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def run_with_bugs(bugs=""):
    """Run the whole suite in a subprocess with BUGS set.

    A subprocess rather than an import because the agent reads BUGS at module
    load. Reloading modules to change a global is the kind of clever that breaks
    silently later.
    """
    env = dict(os.environ, BUGS=bugs)
    proc = subprocess.run(
        [sys.executable, "-m", "evals.runner"],
        cwd=ROOT, env=env, capture_output=True, text=True)
    return proc.returncode, proc.stdout


ALL_BUGS = [
    ("router_prefers_search", "routing"),
    ("retrieval_ignores_city", "retrieval"),
    ("retrieval_returns_everything", "retrieval"),
    ("tool_rounds_wrong", "tool_call"),
    ("tool_skips_booking", "tool_call"),
    ("generation_hallucinates_price", "generation"),
]


def test_clean_baseline_passes():
    """With no bugs the suite must be green, or every other test is meaningless."""
    code, out = run_with_bugs("")
    assert code == 0, f"clean run failed:\n{out}"
    assert "stable fail: 0" in out
    assert "FLAKY: 0" in out, "the deterministic agent must not be flaky"


@pytest.mark.parametrize("bug,expected_stage", ALL_BUGS)
def test_bug_is_detected(bug, expected_stage):
    """Every seeded bug must fail the build. A suite that cannot fail is decoration."""
    code, out = run_with_bugs(bug)
    assert code == 1, f"{bug} was NOT detected:\n{out}"


@pytest.mark.parametrize("bug,expected_stage", ALL_BUGS)
def test_bug_is_attributed_to_the_right_stage(bug, expected_stage):
    """Detection is not enough — it has to point at the stage that broke."""
    code, out = run_with_bugs(bug)
    section = out.split("FAILURES BY STAGE")[1].split("BY GROUP")[0]
    assert expected_stage in section, (
        f"{bug} should be blamed on {expected_stage}, got:\n{section}")


# --- unit tests for the checks that have been wrong before -----------------

def test_forbidden_does_not_false_positive_on_longer_number():
    """Regression: '1400 EUR' was flagged as containing forbidden '400 EUR'."""
    from evals.assertions import Status
    from evals import assertions
    r = assertions.check_forbidden("Three-bedroom, 1400 EUR/month.", ["400 EUR"])
    assert r.status is Status.PASS, "boundary check regressed - substring matching is back"

    r2 = assertions.check_forbidden("Some listings from 400 EUR/month.", ["400 EUR"])
    assert r2.status is Status.FAIL, "a genuine forbidden string was missed"


def test_grounding_allows_tool_computed_average():
    """An average is legitimate even though it appears in no source document."""
    from agent import agent
    from evals import assertions
    text, trace = agent.run("What flats do you have in Seville?")
    from evals.assertions import Status
    r = assertions.check_grounding(text, trace)
    assert r.status is Status.PASS, f"tool-computed average wrongly flagged: {r.detail}"


def test_grounding_catches_invented_figure():
    from agent import agent
    from evals import assertions
    _, trace = agent.run("What flats do you have in Seville?")
    from evals.assertions import Status
    r = assertions.check_grounding("Some listings start from 400 EUR/month.", trace)
    assert r.status is Status.FAIL
    assert 400 in r.meta["ungrounded"]


def test_tool_results_recomputes_independently():
    """Regression: the suite checked which tools ran but never their output."""
    from agent import agent
    from evals import assertions
    _, trace = agent.run("What flats do you have in Seville?")
    from evals.assertions import Status
    r = assertions.check_tool_results(trace)
    assert r.status is Status.PASS

    # Corrupt the tool result and confirm the oracle notices.
    trace.get("tool_call")["calls"][0]["result"] = 1
    r2 = assertions.check_tool_results(trace)
    assert r2.status is Status.FAIL


def test_no_booking_when_nothing_matched():
    """Regression: a booking word plus ZERO matching listings still fired
    book_viewing with listing_id=None, so the answer read "I couldn't find
    any properties ... I've started a viewing request for you."
    """
    from agent import agent
    text, trace = agent.run("Book a viewing for a 5 bedroom flat in Seville")
    assert "book_viewing" not in trace.get("tool_call")["names"]
    assert "viewing request" not in text


def test_tool_results_catches_booking_of_unretrieved_listing():
    """The oracle must reject a booking for a listing retrieval never returned."""
    from agent import agent
    from evals import assertions
    from evals.assertions import Status
    _, trace = agent.run("Book a viewing for a 2 bedroom flat in Seville")
    r = assertions.check_tool_results(trace)
    assert r.status is Status.PASS

    booking = next(c for c in trace.get("tool_call")["calls"]
                   if c["name"] == "book_viewing")
    booking["args"]["listing_id"] = "L999"
    r2 = assertions.check_tool_results(trace)
    assert r2.status is Status.FAIL


def test_attribution_picks_earliest_stage():
    """Bad retrieval makes generation look broken too. Blame the cause."""
    from evals.runner import attribute
    from evals.assertions import Result, Status
    results = [
        Result("intent", "routing", Status.PASS),
        Result("retrieval", "retrieval", Status.FAIL),
        Result("grounding", "generation", Status.FAIL),
    ]
    assert attribute(results) == "retrieval"


def test_dataset_is_well_formed():
    """Cheap structural check. A typo'd expectation silently weakens the suite."""
    import json
    with open(os.path.join(ROOT, "evals", "dataset.json"), encoding="utf-8") as f:
        cases = json.load(f)["cases"]

    assert len(cases) >= 25
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"

    valid_intents = {"search", "policy", "chitchat"}
    for c in cases:
        exp = c["expect"]
        assert exp["intent"] in valid_intents, f"{c['id']}: bad intent"
        assert "rubric" in exp, f"{c['id']}: missing rubric"
        assert exp.get("judge_keywords"), f"{c['id']}: missing judge_keywords"
        assert isinstance(exp.get("doc_ids", []), list)


# --- the four-state model --------------------------------------------------
#
# These exist because "N/A" is a hiding place if nothing watches it. Each one
# pins a decision we argued about rather than a behaviour we stumbled into.

def test_checks_return_na_rather_than_passing_vacuously():
    """A check with nothing to look at must not report success.

    All three of these previously returned PASS. That is how 21 of 26 cases
    came to be 'passing' a forbidden-content check with no forbidden list.
    """
    from agent import agent
    from evals import assertions
    from evals.assertions import Status

    r = assertions.check_forbidden("anything at all", [])
    assert r.status is Status.NA, "empty forbidden list is not a pass"

    _, trace = agent.run("Hello")
    assert assertions.check_tool_results(trace).status is Status.NA, \
        "no tool calls means nothing to recompute"

    r = assertions.check_grounding("No prices are mentioned here.", trace)
    assert r.status is Status.NA, "no figures quoted is not a grounded answer"


def test_attribution_ignores_na():
    """An N/A check has no stage to blame — it must not enter attribution."""
    from evals.runner import attribute
    from evals.assertions import Result, Status
    assert attribute([
        Result("intent", "routing", Status.PASS),
        Result("forbidden_content", "generation", Status.NA),
    ]) is None


def test_error_blocks_the_build():
    """ERROR is a harness defect. Silently tolerating it recreates fail-open."""
    from evals.runner import attribute, outcome
    from evals.assertions import Result, Status
    results = [
        Result("intent", "routing", Status.PASS),
        Result("grounding", "generation", Status.ERROR),
    ]
    assert attribute(results) == "generation"
    assert outcome(results) == "fail"


def test_all_na_is_vacuous_not_pass():
    """A case that asserted nothing is not a case that passed."""
    from evals.runner import outcome
    from evals.assertions import Result, Status
    assert outcome([
        Result("forbidden_content", "generation", Status.NA),
        Result("grounding", "generation", Status.NA),
    ]) == "vacuous"

    assert outcome([
        Result("intent", "routing", Status.PASS),
        Result("grounding", "generation", Status.NA),
    ]) == "pass", "one real check evaluating is enough to be a pass"


def test_na_counts_are_reported_per_check():
    """Coverage loss is invisible unless something counts it."""
    from evals import runner
    rows, name = runner.run(runs=1)
    summary = runner.summarise(rows, name, 1)
    assert "na_by_check" in summary
    assert summary["na_by_check"].get("forbidden_content", 0) > 0, \
        "most cases define no forbidden list; that must show up as N/A"
    assert all("na_by_check" in r for r in rows), "per-case N/A counts missing"
