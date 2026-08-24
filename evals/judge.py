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
import time

from evals.cache import Cache


class JudgeUnavailable(RuntimeError):
    """The judge cannot answer right now and retrying will not help today.

    Distinct from a transient error on purpose. A per-minute rate limit is
    worth sleeping through; a per-DAY quota is not, and a harness that blocks
    for 28 minutes hoping otherwise is a harness nobody runs twice.
    """


# One shared cache per process. Set JUDGE_CACHE=0 to bypass it entirely
# (no reads, no writes — which also loses resumability, so prefer a new TAG).
CACHE = Cache(enabled=os.environ.get("JUDGE_CACHE", "1") != "0")

# Experiment namespace. Bump it for a clean full run that is still resumable.
# See Cache.key for why mixing vintages quietly biases a comparison.
TAG = os.environ.get("JUDGE_TAG", "v1")


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

    def score(self, case, text, trace=None, nonce=0):
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
    """A real judge, in three configurations, so the effect of each change is
    measurable rather than assumed.

        anchored=False, with_context=False   "openai-vague"
            Score 1-5 against a one-line rubric. What most teams ship first.

        anchored=True,  with_context=False   "openai-anchored"
            Same model, same answer, but given the SAME 1-5 anchors the human
            rater was given (evals/rubric.py). Isolates the effect of rubric
            anchoring with everything else held constant.

        anchored=True,  with_context=True    "openai-context"
            Additionally shown the documents retrieved for that query. This is
            the one that tests the session's central finding: a rater without
            the source material cannot judge faithfulness, only coherence.
            If context is what fixes the blindness, this config detects the
            "wrong" variant and the other two do not.

    Note on determinism: temperature=0 reduces variance but does NOT make
    OpenAI models deterministic (floating point, batching, kernel scheduling).
    Judge self-consistency is therefore something to measure, not assume --
    see `--repeat` in evals/calibration.py.
    """

    def __init__(self, anchored=True, with_context=False, model=None):
        from openai import OpenAI          # imported lazily; not a hard dependency
        self.client = OpenAI()
        self.model = model or os.environ.get("JUDGE_MODEL", "gpt-4o-mini")
        self.anchored = anchored
        self.with_context = with_context
        # Probed on first call, not assumed. Reasoning models (o-series,
        # gpt-5.x-mini and friends) fix temperature at 1 and reject any
        # attempt to pin it. Capability differences between models are
        # discovered at runtime; hardcoding them ages badly.
        self.supports_temperature = True
        self.name = ("openai-anchored" if anchored else "openai-vague") + (
            "-context" if with_context else "")

    @staticmethod
    def _context_block(trace):
        """The retrieved documents, verbatim, so the judge can check facts."""
        from agent import knowledge
        ids = (trace.get("retrieval") or {}).get("doc_ids", []) if trace else []
        docs = [knowledge.get(i) for i in ids]
        docs = [d for d in docs if d]
        if not docs:
            return "(no documents were retrieved for this query)"
        lines = []
        for d in docs:
            price = f" price={d['price']} EUR/month" if "price" in d else ""
            lines.append(f"- [{d['id']}]{price} {d.get('text', '')}")
        return "\n".join(lines)

    def _prompt(self, case, text, trace):
        from evals import rubric

        parts = ["You are grading a property-search assistant's answer."]

        if self.anchored:
            parts.append("\nScoring scale:\n" + rubric.SCALE + "\n" + rubric.GUIDANCE)
        parts.append(f"\nWhat this particular case should cover:\n"
                     f"{case['expect'].get('rubric', '')}")

        if self.with_context:
            parts.append("\nDocuments the assistant retrieved. Every factual claim "
                         "in the answer must be supported by these. A claim that "
                         "contradicts them is a 1.\n" + self._context_block(trace))

        parts.append(f"\nUser asked:\n{case['query']}")
        parts.append(f"\nAssistant answered:\n{text}")

        if not self.anchored:
            parts.append("\nScore 1-5 on how well the answer satisfies the rubric.\n"
                         "5 = fully satisfies it. 1 = does not satisfy it at all.")

        parts.append('\nReply with JSON only: '
                     '{"score": <1-5>, "reason": "<one short sentence>"}')
        return "\n".join(parts)

    def score(self, case, text, trace=None, nonce=0, max_retries=4):
        """Score one answer. `nonce` distinguishes repeats for cache purposes.

        Retries transient rate limits with exponential backoff; refuses to
        retry a daily quota, which would just hang.
        """
        prompt = self._prompt(case, text, trace)
        cached = CACHE.get(self._key(prompt, nonce))
        if cached is not None:
            return int(cached["score"]), cached.get("reason", "")

        delay = 2.0
        resp = None
        # See the identical note in agent/llm.py: the temperature probe is a
        # discovery, not a retry, so it must not consume the budget — and a
        # probe landing on the final iteration used to fall out of the loop with
        # `resp` unbound.
        attempts_left = max_retries
        while attempts_left > 0:
            kwargs = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            }
            if self.supports_temperature:
                # Reduces variance where allowed. Never eliminates it — even
                # at 0, OpenAI models are not bit-deterministic.
                kwargs["temperature"] = 0
            try:
                resp = self.client.chat.completions.create(**kwargs)
                break
            except Exception as exc:
                msg = str(exc)
                # "does not support 0 with this model" -> the model fixes
                # temperature at its default. Drop the parameter and retry
                # immediately; this costs one wasted call per judge, once.
                if "temperature" in msg and self.supports_temperature:
                    self.supports_temperature = False
                    continue
                attempts_left -= 1
                is_rate = "429" in msg or "rate_limit" in msg
                # A daily quota will not clear inside this run. Fail fast and
                # loudly so the caller can report partial results instead of
                # blocking, and so the cache keeps everything earned so far.
                if is_rate and ("per day" in msg or "RPD" in msg):
                    raise JudgeUnavailable(
                        f"{self.model}: daily request quota exhausted. "
                        f"Cached work is kept; re-run when it resets.") from None
                if is_rate and attempts_left > 0:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise

        if resp is None:
            raise JudgeUnavailable(
                f"{self.model}: {max_retries} attempts produced no response. "
                f"Cached work is kept.")

        data = json.loads(resp.choices[0].message.content)
        score = self._validate(data.get("score"))
        # Written under a key recomputed from the FINAL temperature setting, not
        # the one assumed before the call. On the first request to a model that
        # refuses temperature, the lookup missed at `@t0` and the answer belongs
        # at `@tdefault`; writing it back under the miss key would file a
        # default-temperature measurement as a pinned one, and every later
        # lookup (now correctly at `@tdefault`) would miss it forever.
        #
        # Store the model and a timestamp alongside the verdict. Without them
        # a cache entry cannot tell you WHEN or by WHAT it was produced, and a
        # report built from it cannot disclose its own vintage.
        CACHE.set(self._key(prompt, nonce), {"score": score,
                                             "reason": data.get("reason", ""),
                                             "model": self.model,
                                             "ts": time.time()})
        return score, data.get("reason", "")

    def _key(self, prompt, nonce):
        """Cache key, WITH the temperature actually in force.

        agent/llm.py states the rule and this file broke it: any parameter that
        can change the response is part of the identity of the response. A judge
        pinned to 0 and the same judge running at the model's default are two
        different measurements, and they were sharing a cache entry — so a
        report could serve a pinned score for an unpinned run, or the reverse,
        with nothing on the page to say so.

        temperature=0 encodes as the bare judge name rather than as `@t0`. That
        is not a special case for its own sake: every entry already on disk was
        written by the pinned path, so this keeps 600-odd paid-for results valid
        while giving the unpinned measurement — the one that was being filed
        under the wrong identity — a namespace of its own. Invalidating a cache
        to fix a labelling bug would have made the fix cost real money, which is
        how a correct fix gets postponed.
        """
        name = self.name if self.supports_temperature else f"{self.name}@tdefault"
        return CACHE.key(self.model, name, prompt, nonce, tag=TAG)

    def _validate(self, raw):
        """A score off the 1-5 scale is a protocol violation, not a datum.

        Left unchecked it survives all the way into calibration.kappa(), which
        indexes a confusion matrix by score and dies with a bare KeyError naming
        nothing — three modules and one long API run away from the judge that
        actually misbehaved. Refuse it here, where the model that produced it
        can be named, and do not cache it.
        """
        try:
            score = int(raw)
        except (TypeError, ValueError):
            raise ValueError(
                f"{self.name} ({self.model}) returned a non-numeric score "
                f"{raw!r}; the rubric asks for an integer 1-5") from None
        if not 1 <= score <= 5:
            raise ValueError(
                f"{self.name} ({self.model}) returned {score}, outside the 1-5 "
                f"scale in evals/rubric.py. Not cached — fix the prompt or the "
                f"model, do not clamp, because a clamped score is a fabricated "
                f"measurement.")
        return score


# Name -> factory. calibration.py instantiates several and compares them.
JUDGES = {
    "heuristic":       lambda: HeuristicJudge(),
    "openai-vague":    lambda: OpenAIJudge(anchored=False, with_context=False),
    "openai-anchored": lambda: OpenAIJudge(anchored=True,  with_context=False),
    "openai-context":  lambda: OpenAIJudge(anchored=True,  with_context=True),
}


def get_judge():
    if os.environ.get("JUDGE") == "openai" and os.environ.get("OPENAI_API_KEY"):
        return OpenAIJudge()
    return HeuristicJudge()
