"""Answer variants with known quality, for calibrating a judge.

The agent produces one answer per query and it is always about equally good.
That is useless for calibration: a judge scoring everything 5/5 would look
perfect. So each variant degrades a real answer in ONE controlled way and
carries a `truth` score saying how good it is by construction.

    truth      what the degradation says the answer is worth
    human      what a rater scores it, blind, in evals/label.py
    judge      what the LLM-as-judge scores it

EVERY DEGRADATION MUST CARRY A WITNESS
--------------------------------------
The first version of this module trusted its own makers. Two bugs followed,
both of which corrupted the reference standard rather than the code:

  1. `_wrong` and `_omit` had nothing to operate on for a no-results answer,
     returned the input unchanged, and the item was labelled truth=1 anyway.
     A perfect answer carrying a score of 1.

  2. `_omit` removed the average-price sentence — which NO rubric in the
     dataset requires. The item was labelled truth=2 for a fact nobody ever
     asked for. Every judge scored it 5/5 and was correct to; the reference
     was wrong. That bug was invisible to a difference check, because the
     answers genuinely differed.

Bug 2 is the instructive one. A defect that cannot be detected from what the
rater was told is not a defect — it is an unstated preference, and scoring
anyone against it measures nothing.

So every degradation now declares a `witness`: a predicate that inspects the
result and returns a reason if the claimed defect is NOT actually present. If
the witness fails, the variant is SKIPPED rather than emitted with a truth
score it did not earn. Bad reference data becomes unconstructable instead of
merely detectable downstream.

Two categories of stated requirement, and each defect must be covered by one:

  case requirements   judge_keywords / must_not_contain in dataset.json.
                      Machine-checkable. `omission` and `wrong` must break
                      one of these.
  scale criteria      the 1-5 anchors in evals/rubric.py, which explicitly
                      name padding and hedging as defects. `padded` and
                      `hedged` are covered by the scale, so their witness
                      only has to prove the degradation actually happened.
"""

import re

from evals.extract import money_mentions

# Scores on the same 1-5 scale the judge uses, so they compare without rescaling.
TRUTH = {
    "original": 5,
    # padded and hedged score THE SAME. Both leave every required fact present
    # and cost the reader something in getting to it, which is exactly the
    # rubric's anchor for 4: "answers it, minor padding or slight vagueness".
    #
    # hedged was 3 until four independent raters — one human and three judge
    # configurations — all placed it at 4.00. But the consensus is NOT the
    # argument: the argument is that the anchor for 3 reads "partially useful",
    # and a hedged answer containing every required fact is not partially
    # useful, merely irritating. Adjusting a reference because raters disagree
    # with it turns the reference into a summary of rater opinion, after which
    # "human vs truth" measures nothing.
    #
    # The two KINDS are kept separate even though they share a score, so the
    # report can still show them apart. Merge the grading, not the observation.
    "padded": 4,
    "hedged": 4,
    "omission": 2,        # a REQUIRED fact — one a rubric names — is gone
    "wrong": 1,           # confidently false
    "verbose_wrong": 1,   # ...and fluent, confident and long while being false
}

_PADDING = (
    " I hope this helps with your search. Please let me know if you would "
    "like any further details about these properties, their availability, or "
    "the surrounding neighbourhoods, and I would be delighted to assist you "
    "further with anything else you may need."
)

_HEDGE_PREFIX = "Based on what I could find,"
_HEDGES = ("I think ", "it seems that ", "as far as I can tell, ", "possibly ")

_NO_RESULTS = ("couldn't find", "could not find", "no properties")


def _sentences(text):
    return [s for s in re.split(r"(?<=\.)\s+", text) if s.strip()]


def _decap(s):
    """Lowercase a leading capital, unless it is the pronoun 'I'.

    Without this, hedging "I found 1 property" produces "i found", and a rater
    would be scoring the typo rather than the hedging. A degradation must vary
    exactly one thing.
    """
    if not s or s.startswith("I ") or s == "I":
        return s
    return s[0].lower() + s[1:]


# --- the degradations ------------------------------------------------------

def _pad(text, case):
    return text + _PADDING


def _hedge(text, case):
    out = _HEDGE_PREFIX + " " + _decap(text)
    parts = out.split(". ")
    for i in range(1, len(parts)):
        if parts[i]:
            parts[i] = _HEDGES[i % len(_HEDGES)] + _decap(parts[i])
    return ". ".join(parts)


def _omit(text, case):
    """Remove a sentence carrying a fact the CASE RUBRIC requires.

    Previously this removed the average-price sentence, which no rubric asks
    for — so the 'defect' was undetectable in principle and truth=2 was a
    fiction. Now it targets judge_keywords, which are the dataset's own
    statement of what the answer must contain.
    """
    keywords = case["expect"].get("judge_keywords") or []
    sents = _sentences(text)

    # Prefer a keyword that lives in exactly one sentence — removing that
    # sentence genuinely removes the requirement rather than one mention of it.
    for kw in keywords:
        holders = [i for i, s in enumerate(sents) if kw.lower() in s.lower()]
        if len(holders) == 1:
            del sents[holders[0]]
            return " ".join(sents)
    return text          # no clean removal available; the witness will reject


def _wrong(text, case):
    """Keep the shape, corrupt a fact."""
    # A no-results answer has no figures to corrupt. Fabricating a result set
    # is the realistic failure here, and it is exactly what the
    # search/no-results stratum exists to catch.
    if any(p in text.lower() for p in _NO_RESULTS):
        return ("I found 2 matching properties. Two-bedroom flat in Triana, "
                "Seville. Furnished, balcony, 950 EUR/month.")
    return re.sub(r"(\d{3,5})(\s*EUR)",
                  lambda m: str(int(m.group(1)) + 150) + m.group(2), text)


def _verbose_wrong(text, case):
    """Long, fluent, confident and false — the realistic production failure.

    Exists to break a confound rather than to model a new defect. In the
    unbalanced set, length PREDICTED quality (corr(length, truth) = +0.34):
    padding made answers long and good-ish, omission made them short and bad.
    A rater that measured nothing but length would have scored well without
    understanding anything, so the dataset could not distinguish a good rater
    from a cheap proxy.

    Adding this one variant takes that correlation to -0.07. Adding a
    short-and-complete variant as well overshoots to -0.21 — you can absolutely
    over-correct a bias into its mirror image, so the balance is checked
    empirically rather than assumed.
    """
    return _pad(_wrong(text, case), case)


# --- the witnesses ---------------------------------------------------------
# Each returns None if the claimed defect is genuinely present, or a string
# explaining why the variant does not deserve its truth score.

def _w_changed(original, variant, case):
    if variant == original:
        return "identical to the original"
    return None


def _w_padded(original, variant, case):
    if (bad := _w_changed(original, variant, case)):
        return bad
    if len(variant) < len(original) * 1.4:
        return f"only {len(variant) - len(original)} chars longer; not padding"
    if money_mentions(variant).values != money_mentions(original).values:
        return "padding changed a figure; that is a different defect"
    return None


def _w_hedged(original, variant, case):
    if (bad := _w_changed(original, variant, case)):
        return bad
    # The prefix counts. A one-sentence answer has no sentence boundaries for
    # the per-sentence markers to attach to, but "Based on what I could find,
    # I couldn't find any properties" is unambiguously hedged. An over-strict
    # witness that rejects a valid variant is a coverage loss, not a safety win.
    markers = (_HEDGE_PREFIX,) + _HEDGES
    added = sum(m.strip() in variant and m.strip() not in original for m in markers)
    if added < 1:
        return "no hedge markers were added"
    if money_mentions(variant).values != money_mentions(original).values:
        return "hedging changed a figure; that is a different defect"
    return None


def _w_omission(original, variant, case):
    """The removed fact must be one the dataset actually requires."""
    if (bad := _w_changed(original, variant, case)):
        return bad
    keywords = case["expect"].get("judge_keywords") or []
    present_before = [k for k in keywords if k.lower() in original.lower()]
    lost = [k for k in present_before if k.lower() not in variant.lower()]
    if not lost:
        return (f"no required keyword was removed (rubric requires "
                f"{present_before}); the 'missing fact' is unstated")
    return None


def _w_wrong(original, variant, case):
    """Something asserted must now be false, not merely different."""
    if (bad := _w_changed(original, variant, case)):
        return bad
    before, after = money_mentions(original).values, money_mentions(variant).values
    if after - before:
        return None                      # asserts a figure it did not before
    if any(p in original.lower() for p in _NO_RESULTS) and \
            not any(p in variant.lower() for p in _NO_RESULTS):
        return None                      # fabricated a result set from nothing
    return "no factual claim was changed"


def _w_verbose_wrong(original, variant, case):
    """BOTH conditions must hold, or the variant is one of the other defects.

    Longer alone is `padded`. Factually changed alone is `wrong`. This kind
    only earns its truth score by being both at once, so the witness is a
    conjunction rather than the single check the other witnesses use.
    """
    if (bad := _w_changed(original, variant, case)):
        return bad
    if len(variant) < len(original) * 1.4:
        return f"only {len(variant) - len(original)} chars longer; that is just 'wrong'"
    if (why := _w_wrong(original, variant, case)):
        return f"no false claim, so this is just 'padded' ({why})"
    return None


MAKERS = {
    "original": (lambda t, c: t, lambda o, v, c: None),
    "padded":   (_pad,   _w_padded),
    "hedged":   (_hedge, _w_hedged),
    "omission": (_omit,  _w_omission),
    "wrong":         (_wrong, _w_wrong),
    "verbose_wrong": (_verbose_wrong, _w_verbose_wrong),
}


def validate(kind, original, variant, case):
    """None if `variant` genuinely exhibits `kind`, else the reason it does not.

    Exposed so the calibration report can re-check reference data it did not
    generate — defence in depth. The generator refuses to emit bad variants;
    the consumer verifies rather than trusts.
    """
    _make, witness = MAKERS[kind]
    return witness(original, variant, case)


def variants_for(case, answer):
    """One base answer -> up to five witnessed variants, plus any skips.

    Returns (variants, skipped). A degradation that cannot be produced for
    this answer is SKIPPED, never emitted with an unearned truth score.
    Skips are returned rather than swallowed: a silently missing variant is
    a coverage gap, and coverage gaps should be visible.
    """
    out, skipped = [], []
    for kind, (make, witness) in MAKERS.items():
        variant = make(answer, case)
        if kind != "original":
            reason = witness(answer, variant, case)
            if reason:
                skipped.append({"case_id": case["id"], "kind": kind, "reason": reason})
                continue
        out.append({"query": case["query"], "case_id": case["id"], "kind": kind,
                    "truth": TRUTH[kind], "answer": variant})
    return out, skipped


def build_set(cases, agent_run, limit=6):
    """Build a calibration set from the first `limit` cases of the dataset."""
    items, skipped = [], []
    for case in cases[:limit]:
        answer, _trace = agent_run(case["query"])
        vs, sk = variants_for(case, answer)
        items.extend(vs)
        skipped.extend(sk)
    return items, skipped
