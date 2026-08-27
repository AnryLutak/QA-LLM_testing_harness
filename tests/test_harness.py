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


def test_confirmed_forbidden_hit_is_not_hidden_behind_a_parse_error():
    """A known violation must not be re-filed as a harness defect.

    Both ERROR and FAIL block the build, so this never went green — it went to
    the wrong engineer. ERROR reads 'fix your parser'; the answer had already
    been caught saying a forbidden thing.
    """
    from evals import assertions
    from evals.assertions import Status

    # "1.4k EUR" is money-shaped and deliberately unparseable, so the amount
    # arm cannot conclude. The string arm already has.
    r = assertions.check_forbidden(
        "I've started a viewing request for you. Others from 1.4k EUR.",
        forbidden=["viewing request"], forbidden_amounts=[400])
    assert r.status is Status.FAIL, r.detail
    assert "viewing request" in r.detail
    assert "1.4k EUR" in r.detail, "the unread amount must stay visible"

    # ...and with nothing confirmed, unreadable money still fails closed.
    r = assertions.check_forbidden("Others from 1.4k EUR.",
                                   forbidden=["viewing request"],
                                   forbidden_amounts=[400])
    assert r.status is Status.ERROR, r.detail


def _bare_judge(name="openai-anchored", model="gpt-4o-mini", pinned=True):
    """An OpenAIJudge with no client. __init__ imports openai, which CI does not
    install — and none of the key/validation logic needs a network."""
    from evals.judge import OpenAIJudge
    j = object.__new__(OpenAIJudge)
    j.name, j.model, j.supports_temperature = name, model, pinned
    return j


def test_judge_cache_key_carries_the_temperature_actually_used():
    """agent/llm.py states the rule; judge.py was breaking it.

    Any parameter that can change the response is part of the identity of the
    response. A judge pinned to 0 and the same judge at the model's default were
    sharing one cache entry, so a report could serve a pinned score for an
    unpinned run with nothing on the page to say so.
    """
    from evals.cache import Cache
    from evals.judge import TAG

    pinned, unpinned = _bare_judge(pinned=True), _bare_judge(pinned=False)
    assert pinned._key("P", 0) != unpinned._key("P", 0)

    # ...without invalidating what is already on disk. Every existing entry was
    # written by the pinned path, so temperature=0 must keep encoding as the
    # bare judge name. A correct fix that costs 600 paid API calls is a correct
    # fix that gets postponed.
    assert pinned._key("P", 0) == Cache.key(
        "gpt-4o-mini", "openai-anchored", "P", 0, tag=TAG)


def test_judge_refuses_off_scale_scores_rather_than_clamping():
    """A clamped score is a fabricated measurement."""
    import pytest as _pytest
    j = _bare_judge()
    assert j._validate(4) == 4 and j._validate("5") == 5
    for bad in (0, 6, None, "high"):
        with _pytest.raises(ValueError):
            j._validate(bad)


def test_kappa_rejects_off_scale_scores_by_name():
    """`KeyError: 6` names neither the rater nor the item."""
    import pytest as _pytest
    from evals.calibration import kappa

    with _pytest.raises(ValueError, match="not on the"):
        kappa([1, 2, 6], [1, 2, 3])
    assert kappa([1, 2, 3], [1, 2, 3]) == 1.0


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


def test_undeclared_expectations_are_na_not_vacuous_passes():
    """`.get(key, [])` cannot tell 'declares nothing' from 'declares empty'.

    An empty expectation compared against an empty result is an 'exact match',
    so a case that never stated a retrieval expectation PASSED its retrieval
    check. Same for tools. The checks were right; the arguments were fail-open.
    """
    from agent import agent
    from evals import assertions
    from evals.assertions import Status

    _, trace = agent.run("Hello")

    assert assertions.check_retrieval(trace, None).status is Status.NA
    assert assertions.check_tools(trace, None).status is Status.NA
    assert assertions.check_intent(trace, None).status is Status.NA

    # ...and declared-empty still asserts. This is the half that must not break:
    # several chitchat cases genuinely require that nothing is retrieved.
    assert assertions.check_retrieval(trace, []).status is Status.PASS
    assert assertions.check_tools(trace, []).status is Status.PASS


def test_a_case_that_asserts_nothing_is_vacuous_and_fails_the_build(tmp_path):
    """End to end, because `outcome()` returning 'vacuous' in a unit test proved
    nothing about whether the verdict was REACHABLE.

    It was not. run_all always included check_intent, which returns PASS or FAIL
    and never N/A, so no case could ever be all-N/A and the report printed
    `VACUOUS: 0` on every run of its life. A verdict that cannot occur is
    indistinguishable from a verdict that never occurs, and the second one reads
    as an invariant being upheld.
    """
    import json
    dataset = tmp_path / "vacuous.json"
    dataset.write_text(json.dumps({"cases": [{
        "id": "vac-001",
        "group": "vacuous",
        "query": "Hello",
        # Deliberately declares no intent, no doc_ids, no tools, no forbidden
        # content. A chitchat answer quotes no figures and calls no tools, so
        # every one of the six checks has nothing to look at.
        "expect": {"rubric": "greets the user", "judge_keywords": ["help"]},
    }]}))

    proc = subprocess.run(
        [sys.executable, "-m", "evals.runner", "--dataset", str(dataset)],
        cwd=ROOT, env=dict(os.environ, BUGS=""), capture_output=True, text=True)

    assert "VACUOUS: 1" in proc.stdout, proc.stdout
    assert proc.returncode == 1, (
        "a case that executed and asserted nothing must not exit 0:\n" + proc.stdout)


def test_generalisation_interval_is_not_degenerate_when_everything_passes():
    """The all-green run is where a percentile bootstrap silently collapses.

    Every case rate is 1.0, so every resample is 1.0, so the interval was
    [100%, 100%] — the same 'certain from 26 observations' claim that wilson()
    exists in this file to refuse, arriving by a different route and printed
    under the heading the report tells you to trust.
    """
    from evals.runner import bootstrap_case_ci

    lo, hi = bootstrap_case_ci([1.0] * 26, runs=1)
    assert hi == 1.0
    assert lo < 0.95, f"26/26 must not imply near-certainty, got [{lo}, {hi}]"

    lo0, hi0 = bootstrap_case_ci([0.0] * 26, runs=1)
    assert lo0 == 0.0
    assert hi0 > 0.05, f"0/26 must not rule out failure, got [{lo0}, {hi0}]"

    # Monotone: losing a case must never NARROW the interval. It did — 25/26
    # reported [88.5%, 100%] against 26/26's [100%, 100%] — and a report where
    # a regression buys confidence is worse than one with no interval at all.
    widths = [hi - lo for lo, hi in
              (bootstrap_case_ci([1.0] * (26 - k) + [0.0] * k, runs=1)
               for k in range(4))]
    assert widths == sorted(widths), f"interval must widen as cases fail: {widths}"


# --- is this N observations, or one observation counted N times? -----------
#
# The reproducibility interval and the per-run spread are the two headline
# numbers on the report, and both assume `--runs N` collected N draws. On the
# live path that assumption is a property of the CACHE KEY, so these pin the
# key and the instrument check that shouts when it stops holding.

def _one_live_case(tmp_path):
    import json
    dataset = tmp_path / "live.json"
    dataset.write_text(json.dumps({"cases": [{
        "id": "live-001",
        "group": "search/basic",
        "query": "What flats do you have in Seville?",
        "expect": {"intent": "search", "rubric": "lists Seville flats",
                   "judge_keywords": ["found"]},
    }]}))
    return str(dataset)


def test_the_run_index_reaches_the_generation_cache_key(tmp_path, monkeypatch):
    """`--runs N` on the live path must be N generations, not one served N times.

    agent.run takes `attempt` precisely so run i's completion is cached apart
    from run j's (evals/cache.py states the rule; evals/redteam.py has always
    passed it). This runner did not, so every run of a case looked up
    (model, prompt, attempt=0): measured at TEMP=0 with --runs 20, 520
    "observations" from 26 model calls, reproducibility CI [85.4%, 90.9%], and
    per-run sd 0.0% printed under "this is what CI would have printed on each
    of those runs".

    Note what the failure looks like: not a red build, a STABLER one.
    """
    from agent import llm
    from evals import runner

    seen = []

    def fake_generate(query, docs, calls, spotlight=False, attempt=0, **kw):
        seen.append(attempt)
        return f"I found 1 matching properties. Answer number {attempt}."

    monkeypatch.setattr(llm, "enabled", lambda: True)
    monkeypatch.setattr(llm, "generate", fake_generate)

    rows, _ = runner.run(_one_live_case(tmp_path), runs=3)

    assert seen == [0, 1, 2], f"the run index never reached the model: {seen}"
    assert rows[0]["distinct_answers"] == 3, (
        "three runs produced fewer than three distinct answers, so the rate "
        "computed from them is a property of the cache")


def test_a_degenerate_run_is_shouted_about_rather_than_read_as_stability(
        tmp_path, monkeypatch, capsys):
    """One answer per case, repeated, must not print as a narrow interval.

    evals/redteam.py has asked this question in its `uniq` column since a pinned
    sampler made every attack rate 0% or 100%. The same failure here is quieter
    and therefore worse: a degenerate eval run does not look broken, it looks
    reproducible.
    """
    from agent import llm
    from evals import runner

    monkeypatch.setattr(llm, "enabled", lambda: True)
    monkeypatch.setattr(llm, "generate",
                        lambda *a, **k: "I found 1 matching properties.")

    rows, name = runner.run(_one_live_case(tmp_path), runs=4)
    summary = runner.summarise(rows, name, 4)

    assert summary["degenerate_cases"] == summary["cases"]
    assert summary["variance_expected"], \
        "a live model with --runs>1 is a configuration that asked for variance"

    runner.print_report(rows, summary)
    out = capsys.readouterr().out
    assert "DEGENERATE SAMPLING" in out, out[-1500:]
    assert "1 of 1 cases varied" not in out, "the count is the wrong way round"


def test_the_degeneracy_alarm_stays_quiet_where_TEMP_0_makes_it_expected():
    """At TEMP=0 the agent is a lookup table and one answer per case is the
    documented behaviour, not an alarm. A check that fires on the default
    configuration gets muted, and a muted instrument check is worth nothing."""
    from evals import runner
    rows, name = runner.run(runs=2)
    summary = runner.summarise(rows, name, 2)
    assert summary["degenerate_cases"] == summary["cases"]
    assert not summary["variance_expected"], \
        "TEMP=0 with no live model did not ask for a stochastic system"


def test_a_small_figure_is_a_grounding_failure_not_a_harness_error():
    """`50 EUR` is not a mis-read, it is fifty euros.

    evals/extract.py refused every amount under 100 as implausible, and the
    refusal went to .unparseable — the channel that means "the harness cannot
    read this". check_grounding then reported ERROR, sending someone to fix a
    parser over an answer that had quoted a number no document supports. Both
    block the build, so it never went green; it went to the wrong engineer.
    """
    from agent import agent
    from evals import assertions
    from evals.assertions import Status

    _, trace = agent.run("What flats do you have in Seville?")
    r = assertions.check_grounding("Others start from 50 EUR/month.", trace)
    assert r.status is Status.FAIL, r.detail
    assert 50 in r.meta["ungrounded"]

    # ...and the ceiling still fails closed, because THAT refusal is a genuine
    # "I have probably mis-grouped a separator" rather than a small number.
    r2 = assertions.check_grounding("Others start from €12345678 a month.", trace)
    assert r2.status is Status.ERROR, r2.detail


def test_na_counts_are_reported_per_check():
    """Coverage loss is invisible unless something counts it."""
    from evals import runner
    rows, name = runner.run(runs=1)
    summary = runner.summarise(rows, name, 1)
    assert "na_by_check" in summary
    assert summary["na_by_check"].get("forbidden_content", 0) > 0, \
        "most cases define no forbidden list; that must show up as N/A"
    assert all("na_by_check" in r for r in rows), "per-case N/A counts missing"
