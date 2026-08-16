"""LLM-as-judge for the part that genuinely needs judgement.

Only the free-text quality of the answer is judged. Intent, retrieval, tool
calls and grounding are asserted in assertions.py, because a judge is the wrong
instrument for anything you can check exactly.

Two implementations:

  HeuristicJudge  (default) — deterministic, offline, free. Runs in CI with no
                  API key so anyone can clone this repo and get a green build.
  OpenAIJudge     — the real thing, enabled with JUDGE=openai and an API key.

Known biases of LLM judges, and what is done about them here:

  position bias      — a judge prefers whichever answer it sees first.
                       Mitigated by scoring one answer against a fixed rubric
                       rather than comparing two answers.
  verbosity bias     — longer answers score higher regardless of quality.
                       Mitigated by a rubric that scores against specific
                       required content, and by asserting on grounding
                       separately so padding cannot buy a better score.
  self-preference    — a judge favours text produced by the same model family.
                       Not solved here. If it mattered, the judge should be a
                       different model family from the one under test.
  poor calibration   — scores drift between runs and versions.
                       Mitigated by pinning temperature to 0, pinning the model
                       version, and treating the score as a threshold rather
                       than a metric to optimise.

None of this makes a judge trustworthy on its own. It is a smoke alarm, not a
specification — which is why a failing judge score is reported as a warning and
a failing assertion fails the build.
"""

import json
import os
import re


def _contains(text, term):
    """Whole-token containment, so 'bed' is not satisfied by 'bedroom'."""
    return re.search(r"(?<![\w.])" + re.escape(term) + r"(?![\w.])",
                     text, re.IGNORECASE) is not None


class HeuristicJudge:
    """Deterministic stand-in. NOT a judge — a keyword proxy wearing a judge's
    interface.

    Be clear-eyed about what this is. It checks whether required terms appear
    in the answer. That is a rung-2 assertion, not an act of judgement, and it
    cannot evaluate anything a judge is actually for: tone, coherence,
    faithfulness, whether the answer addressed the question asked. Its only
    real virtue is that CI runs green with no API key.

    The consequence, which matters: a green run of this proxy is NOT evidence
    that the judging layer works. It is evidence that some strings are present.
    Anything you want to claim about judge quality has to come from
    JUDGE=openai plus a calibration check against human labels.
    """

    name = "heuristic"

    def score(self, case, text, trace):
        """Score on judge_keywords, not on the rubric prose.

        The first version tokenised the rubric itself, which meant it was
        looking for words like "mentions" and "invent" in the answer. Twelve of
        twenty-five cases scored below threshold on a completely healthy agent.
        A judge that cries wolf gets ignored, which is worse than no judge.
        """
        keywords = case["expect"].get("judge_keywords")
        if not keywords:
            return 3, "no judge_keywords defined - not scored"

        # Boundary-aware, matching check_forbidden. The previous version used a
        # plain `in` substring test, so the keyword "bed" was satisfied by
        # "bedroom" and "400" by "1400" — the exact false-positive class that
        # was already fixed once in assertions.check_forbidden and then
        # reintroduced here ten lines away. A lenient check inflates the score,
        # which is worse than a noisy one: it fails silently.
        hit = [k for k in keywords if _contains(text, k)]
        ratio = len(hit) / len(keywords)

        # Linear, so the number means something: 5 = everything the rubric
        # requires is present, 1 = none of it. Previously `1 + round(ratio*4)`
        # returned 3 at ratio 0.5, which passed a threshold of 3 — an answer
        # missing HALF its required content scored a pass. See JUDGE_THRESHOLD
        # in runner.py, now 4.
        score = round(1 + 4 * ratio)

        missing = [k for k in keywords if not _contains(text, k)]
        reason = (f"all {len(keywords)} expected terms present" if not missing
                  else f"{len(hit)}/{len(keywords)} present, missing {missing}")
        return score, reason


class OpenAIJudge:
    """Real judge. Only used when JUDGE=openai and OPENAI_API_KEY are set."""

    name = "openai"

    PROMPT = """You are grading a property-search assistant's answer.

Rubric for this case:
{rubric}

User asked:
{query}

Assistant answered:
{answer}

Score 1-5 on how well the answer satisfies the rubric.
5 = fully satisfies it. 1 = does not satisfy it at all.
Do not reward length. Do not reward confidence. Reward only whether the
rubric's requirements are met.

Reply with JSON only: {{"score": <1-5>, "reason": "<one short sentence>"}}"""

    def __init__(self):
        from openai import OpenAI          # imported lazily; not a hard dependency
        self.client = OpenAI()
        self.model = os.environ.get("JUDGE_MODEL", "gpt-4o-mini")

    def score(self, case, text, trace):
        prompt = self.PROMPT.format(
            rubric=case["expect"].get("rubric", ""),
            query=case["query"], answer=text)
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,                 # calibration: never sample the judge
            response_format={"type": "json_object"},
        )
        data = json.loads(resp.choices[0].message.content)
        return int(data["score"]), data.get("reason", "")


def get_judge():
    if os.environ.get("JUDGE") == "openai" and os.environ.get("OPENAI_API_KEY"):
        return OpenAIJudge()
    return HeuristicJudge()
