"""Controlled non-determinism.

The agent in agent.py is deterministic keyword logic: same query in, same bytes
out, every time. That makes the suite fast, free and offline — and it also means
the suite has never once faced the defining property of an LLM feature, which is
that it does *not* do that.

This module injects the three kinds of variation a real model introduces:

    surface    the same content, worded differently  (paraphrase)
    routing    borderline inputs classified inconsistently between runs
    retrieval  marginal documents in on one run, out on the next

Controlled by TEMP (0.0 - 1.0):

    TEMP=0            hard no-op. Every function returns its input untouched,
                      so the deterministic suite stays bit-identical to before.
    TEMP=0.3          realistic well-behaved production system
    TEMP=1.0          a system you would be right to be frightened of

Two design decisions worth understanding, because they are what make the
resulting numbers behave like a real system rather than like a coin:

1. NOISE IS NOT UNIFORM. Real systems do not fail at random — they fail on
   borderline inputs. A query that trips both the policy and the search
   keyword sets is far more likely to be misrouted than an unambiguous one.
   So the variance concentrates in specific groups of the dataset rather than
   smearing evenly across it. That is precisely why a single aggregate pass
   rate is a bad summary: it averages a rock-stable group together with a
   coin-flip group and reports something true of neither.

2. SURFACE VARIATION IS NEAR-CERTAIN, NOT OCCASIONAL. A real model rewords its
   answer essentially every run. Behavioural errors are the rare event;
   rewording is the default. Assertions that depend on exact phrasing
   therefore do not degrade gracefully — they degrade immediately.

Reproducibility: pass a seeded Random to agent.run(). The runner seeds per
(case, run_index) so a specific run can be replayed exactly, while the sequence
across runs still varies.
"""

import os
import random
import re

TEMP = float(os.environ.get("TEMP", "0") or 0)


def rng_for(seed, case_id, run_index):
    """Deterministic per-(case, run) stream, or true randomness if seed is None."""
    if seed is None:
        return random.Random()
    return random.Random(f"{seed}:{case_id}:{run_index}")


# --------------------------------------------------------------------------
# routing
# --------------------------------------------------------------------------

def maybe_misroute(intent, ambiguous, rng, temp=None):
    """Flip the intent occasionally; much more often when the query is ambiguous.

    p = temp * 0.50 for an ambiguous query
    p = temp * 0.03 for a clear one

    A ~17x difference, which is roughly what a real classifier looks like near
    its decision boundary versus far from it.
    """
    temp = TEMP if temp is None else temp
    if temp <= 0 or rng is None:
        return intent
    p = temp * (0.50 if ambiguous else 0.03)
    if rng.random() < p:
        if intent == "policy":
            return "search"
        if intent == "search":
            return "policy"
    return intent


# --------------------------------------------------------------------------
# retrieval
# --------------------------------------------------------------------------

def perturb_retrieval(docs, all_docs, rng, temp=None):
    """Drop a marginal document, or pull in a near-miss.

    Modelled on a similarity threshold sitting close to a document's score:
    the bigger the result set, the more documents are near the boundary, so
    the more often the set changes between runs.
    """
    temp = TEMP if temp is None else temp
    if temp <= 0 or rng is None or not docs:
        return docs

    p = temp * 0.10 * min(len(docs), 4)

    if rng.random() < p:
        if rng.random() < 0.6 and len(docs) > 1:
            drop = rng.randrange(len(docs))
            return docs[:drop] + docs[drop + 1:]
        outside = [d for d in all_docs if d not in docs]
        if outside:
            return docs + [rng.choice(outside)]
    return docs


# --------------------------------------------------------------------------
# generation
# --------------------------------------------------------------------------

# Each style must render the SAME amount differently. A style that ignores `n`
# would change a fact, not a wording — and the grounding check would correctly
# flag a hallucination that this module invented.
_MONEY_STYLES = [
    lambda n: f"{n} EUR",
    lambda n: f"€{n}",
    lambda n: f"{n} euros",
    lambda n: f"EUR {n}",
    # No-break space as a thousands separator ( ). Common in European
    # formatting and deliberately NOT parseable by evals/extract.py, so this
    # style is what exercises the Status.ERROR path end to end. Amounts under
    # four digits have no group to separate and come out unchanged.
    lambda n: (f"{n[:-3]} {n[-3:]} EUR" if len(n) > 3 else f"{n} EUR"),
]

_OPENERS = [
    "I found {n} matching properties.",
    "There are {n} properties that match.",
    "{n} listings match what you're after.",
    "Here are the {n} matches I have.",
]


def paraphrase(text, rng, temp=None):
    """Reword without changing meaning.

    Applied on nearly every run when temp > 0, because that is how models
    behave. Nothing here changes a single fact — only how it is written.
    """
    temp = TEMP if temp is None else temp
    if temp <= 0 or rng is None:
        return text

    # Money formatting. "1400 EUR" -> "€1400" / "1400 euros" / "EUR 1400".
    def _money(m):
        return _MONEY_STYLES[rng.randrange(len(_MONEY_STYLES))](m.group(1))

    text = re.sub(r"(\d{3,5})\s*EUR", _money, text)

    # Sentence-level rewording of the search preamble.
    m = re.match(r"I found (\d+) matching properties\.", text)
    if m:
        opener = _OPENERS[rng.randrange(len(_OPENERS))].format(n=m.group(1))
        text = opener + text[m.end():]

    if rng.random() < 0.3:
        text = text.replace("I've started a viewing request for you.",
                            "A viewing request is now pending for you.")

    return text


def maybe_drop_average(text, rng, temp=None):
    """Occasionally omit the average-price sentence entirely.

    A content omission rather than a rewording: the model simply does not
    mention something it was supposed to mention. Rare, and much harder to
    notice than a wrong number.
    """
    temp = TEMP if temp is None else temp
    if temp <= 0 or rng is None:
        return text
    if rng.random() < temp * 0.08:
        return re.sub(r"\s*The average price is [^.]*\.", "", text)
    return text
