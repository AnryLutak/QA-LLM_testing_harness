"""Format battery for money extraction.

This file is written BEFORE evals/extract.py exists. That is deliberate: it is
the specification for a module that has not been built, and running it now
should fail at import. A test you have never seen fail is a test you have no
evidence works.

What it pins down
-----------------
`money_mentions(text)` returns an object with two fields:

    .values        set[int]    amounts it successfully read
    .unparseable   list[str]   spans that look like money but could not be read

The second field is the entire point. A parser that returns only values cannot
distinguish "this answer mentions no money" from "this answer mentions money I
could not read", and treating the second as the first is exactly the fail-open
bug that let a hallucinated price through 76% of the time once the answer was
reworded.

That requires two regexes, not one:

    detector   deliberately LOOSE. "is there money-ness here?"
    parser     deliberately STRICT. "what integer is this, exactly?"

Anything the detector finds and the parser cannot resolve goes to
.unparseable. If both are the same expression, .unparseable is always empty
and this whole design collapses back into the bug.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from evals.extract import money_mentions


# ---------------------------------------------------------------------------
# Table 1: formats that must parse to a known value.
#
# Every expected value is a hand-written literal. Never compute an expectation
# using the same logic as the code under test — you would only be asserting
# that the code agrees with itself.
# ---------------------------------------------------------------------------

PARSES = [
    # --- the plain cases, all currently working -------------------------
    pytest.param("400 EUR/month",           {400},        id="amount-then-EUR"),
    pytest.param("EUR 400/month",           {400},        id="EUR-then-amount"),
    pytest.param("€400/month",              {400},        id="symbol-then-amount"),
    pytest.param("400 euros/month",         {400},        id="lowercase-euros"),
    pytest.param("400 Euro/month",          {400},        id="singular-Euro"),
    pytest.param("400EUR",                  {400},        id="no-space"),

    # --- comma as thousands separator, currently working ----------------
    pytest.param("1,400 EUR/month",         {1400},       id="comma-thousands"),
    pytest.param("€1,400",                  {1400},       id="symbol-comma-thousands"),

    # --- space as a thousands separator ----------------------------------
    # These MOVED here from UNPARSEABLE on purpose. They were pinned as
    # unreadable while the parser only knew "." and ","; once it learned the
    # space forms they became ordinary parses. Moving a row between tables is
    # a decision, so it gets a note — deleting it silently is how a battery
    # quietly stops testing the thing it was written for.
    pytest.param("Prices from 1 400 EUR",   {1400},       id="space-thousands"),
    pytest.param("Rent is EUR 1 250/month", {1250},       id="EUR-then-space-thousands"),
    pytest.param("about \u00a01 100 EUR",     {1100},       id="nbsp-thousands"),

    # --- KNOWN FAILING. Spanish/European thousands separator ------------
    # The first is the dangerous one: it does not fail to parse, it parses
    # WRONG, silently, to 400. On a Spanish property site this is the house
    # formatting convention, so grounding would report a hallucination that
    # never happened.
    pytest.param("1.400 EUR/month",         {1400},       id="dot-thousands"),
    pytest.param("EUR 1.400",               {1400},       id="EUR-then-dot-thousands"),
    pytest.param("€1.400 per month",        {1400},       id="symbol-dot-thousands"),

    # --- amounts below the old plausibility floor -------------------------
    # These MOVED here from UNPARSEABLE, and not because anything could not read
    # them: "50 EUR" parsed to 50 and was then refused for being small. The
    # refusal went to .unparseable, which is the channel meaning "the harness
    # cannot read this", so check_grounding reported ERROR — go fix the parser —
    # for an answer that had quoted a figure no document supports. That is FAIL
    # and a different engineer's ticket.
    #
    # The CEILING stays, because that refusal is a different claim: see the
    # implausibly-long-number row below, which is a mis-grouped separator rather
    # than a small number.
    pytest.param("a 50 EUR admin fee",      {50},         id="small-amount"),
    pytest.param("€99 booking deposit",     {99},         id="two-digit-amount"),

    # --- several amounts in one answer ----------------------------------
    pytest.param("400 EUR and 1400 EUR",    {400, 1400},  id="two-amounts"),
    pytest.param(
        "I found 3 properties. The average price is 1.250 EUR/month. "
        "Some listings start from €400/month.",
        {1250, 400},
        id="realistic-sentence-mixed-formats",
    ),

    # --- boundaries. The old bug was "1400 EUR" matching forbidden
    #     "400 EUR"; make sure extraction never splits a number. ---------
    pytest.param("1400 EUR",                {1400},       id="no-substring-split"),
]


# ---------------------------------------------------------------------------
# Table 2: no money present at all. .values empty AND .unparseable empty.
#
# This is the legitimately-N/A case. It must be distinguishable from Table 3.
# ---------------------------------------------------------------------------

NO_MONEY = [
    pytest.param("the average is 950",          id="bare-number-no-currency"),
    pytest.param("rent is 950 per month",       id="bare-number-in-sentence"),
    pytest.param("I found 3 matching properties.", id="count-not-price"),
    pytest.param("No prices are mentioned here.",  id="no-digits"),
    pytest.param("All prices are quoted in euros.", id="currency-word-no-amount"),
    pytest.param("",                            id="empty-string"),
]


# ---------------------------------------------------------------------------
# Table 3: money-ness is present but the value cannot be read.
#
# These must NOT come back as "no money". They are harness defects and the
# runner turns them into Status.ERROR, which blocks the build. Loud beats
# silently wrong.
# ---------------------------------------------------------------------------

UNPARSEABLE = [
    # At least one row must survive here or the two-regex design collapses:
    # with nothing unparseable, ERROR is unreachable and
    # test_detector_is_looser_than_the_parser passes by vacuum.
    pytest.param("about €12345678",  id="implausibly-long-number"),
    pytest.param("from 1.4k EUR",    id="abbreviated-thousands"),
    pytest.param("around 1,4k EUR",  id="abbreviated-thousands-comma"),
]


# ---------------------------------------------------------------------------
# The tests. Written once each; the tables supply the rows.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", PARSES)
def test_known_formats_parse_to_the_right_value(text, expected):
    m = money_mentions(text)
    assert m.values == expected, f"parsed {sorted(m.values)}, expected {sorted(expected)}"
    assert m.unparseable == [], (
        f"a format in the PARSES table should parse cleanly, "
        f"but reported unparseable: {m.unparseable}")


@pytest.mark.parametrize("text", NO_MONEY)
def test_text_without_money_is_empty_and_not_an_error(text):
    m = money_mentions(text)
    assert m.values == set(), f"invented amounts {sorted(m.values)} from text with none"
    assert m.unparseable == [], (
        "text with no money must be cleanly empty, so the caller can report N/A. "
        f"got unparseable={m.unparseable}")


@pytest.mark.parametrize("text", UNPARSEABLE)
def test_money_shaped_but_unreadable_is_flagged_not_dropped(text):
    m = money_mentions(text)
    assert m.unparseable, (
        "this looks like money and could not be parsed, so it must be reported. "
        "Returning an empty result here is the fail-open bug: the caller cannot "
        "tell it apart from 'no money mentioned' and reports a pass.")


# ---------------------------------------------------------------------------
# Properties that are not about a single input.
# ---------------------------------------------------------------------------

def test_detector_is_looser_than_the_parser():
    """The design only works if the two regexes disagree somewhere.

    If .unparseable can never be non-empty, the detector and the parser are
    the same expression and ERROR is unreachable — which is the original bug
    with extra ceremony. This is the one assertion that fails loudly if the
    implementation quietly drops the two-regex design.
    """
    assert money_mentions("from 1.4k EUR").unparseable, \
        "detector and parser appear to be the same expression"


def test_values_are_ints_not_strings():
    """Comparison happens on normalised integers, which is what makes the
    check format-immune. '1,400' and '1.400' and '€1400' are one value."""
    m = money_mentions("1,400 EUR and €1400 and EUR 1.400")
    assert m.values == {1400}, f"got {m.values} — all three spellings are one amount"
    assert all(isinstance(v, int) for v in m.values)


# ---------------------------------------------------------------------------
# Documented gap, deliberately not fixed.
#
# xfail records a decision instead of hiding it. It does not fail the build,
# but if someone later implements number-word parsing this turns XPASS and
# tells you the note is stale. A silent gap is the thing to avoid; a signed
# one is fine.
# ---------------------------------------------------------------------------

@pytest.mark.xfail(reason="scope: numerals only. Spelled-out amounts are not "
                          "detected, so they read as N/A rather than ERROR.",
                   strict=False)
def test_spelled_out_amounts_are_a_known_gap():
    m = money_mentions("Some listings start from four hundred euros a month.")
    assert m.values == {400} or m.unparseable


# ---------------------------------------------------------------------------
# The seeded harness bug.
#
# ERROR is a tripwire: once the parser is fixed it should almost never fire,
# which means nothing exercises it end to end. The answer is NOT to leave a
# real check broken for the demo — it is a labelled, opt-in defect, exactly
# like BUGS= in agent/agent.py. This test keeps that switch honest.
# ---------------------------------------------------------------------------

def test_seeded_naive_parser_makes_ERROR_reachable():
    """HARNESS_BUGS=money_parser_naive must reproduce the original fail-open
    shape: separators become unreadable, so the caller reports ERROR."""
    import subprocess, sys, os
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from evals.extract import money_mentions\n"
        "m = money_mentions('1 400 EUR and 1.400 EUR')\n"
        "assert not m.values, m.values\n"
        "assert len(m.unparseable) == 2, m.unparseable\n"
        "print('ok')\n" % ROOT
    )
    env = dict(os.environ, HARNESS_BUGS="money_parser_naive")
    p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True, env=env, cwd=ROOT)
    assert p.returncode == 0, f"naive mode did not behave as seeded:\n{p.stderr}"


def test_default_parser_is_not_naive():
    """The seeded bug must be OFF by default, or 'fixed' means nothing."""
    m = money_mentions("1 400 EUR and 1.400 EUR")
    assert m.values == {1400}, m.values
    assert m.unparseable == []
