# LLM evaluation harness

A regression suite for a conversational agent, built the way I think LLM systems should be tested: **assert everything you can, judge only what you can't, and make failures point at the stage that broke.**

Runs in about a second. No API key, no install step, no network.

```bash
git clone <this-repo> && cd llm-eval-harness
python3 -m evals.runner
```

```
========================================================================
LLM EVALUATION REPORT
========================================================================
judge: heuristic   cases: 26   passed: 26   failed: 0
task success rate: 100.0%
retrieval precision: 1.000   recall: 1.000
```

---

## The problem

You cannot test an LLM feature by asserting on the output string. The same input produces different text every run, so exact assertions fail constantly and get deleted. The usual response is to hand the whole answer to another model and ask "is this good?", which produces a number that drifts between runs, costs money, and tells you nothing about *where* the system went wrong.

Both approaches share a flaw: they treat the agent as one opaque box. It isn't. It's a pipeline:

```
route  ->  retrieve  ->  tool_call  ->  generate
```

Three of those four stages are **completely deterministic**. Which intent was chosen, which documents came back, which tools fired with which arguments — none of that requires judgement. Only the final prose does.

## The approach

**1. Split deterministic from non-deterministic, and assert on everything deterministic.**

| Stage | How it's checked | Why |
|---|---|---|
| Routing | Exact intent match | It's a classification. Assert it. |
| Retrieval | Set comparison + precision/recall | Missing docs and extra docs are different bugs — reported separately |
| Tool calls | Which tools fired, **and what they returned** | Recomputed independently (see below) |
| Generation — facts | Every figure must trace to a retrieved document | Catches hallucination exactly, with no model |
| Generation — prose | LLM-as-judge against a rubric | The only part that genuinely needs judgement |

Judging what you could have asserted is how eval suites become slow, expensive and vague.

**2. Attribute every failure to the earliest broken stage.**

If retrieval returns the wrong documents, generation will also look wrong — but the generator did its job faithfully with bad input. Reporting both is noise. The runner blames the earliest failing stage, which turns *"the answer was wrong"* into *"retrieval dropped the city filter"* — the difference between a red build and a ticket someone can pick up.

```
FAILURES BY STAGE (earliest broken stage)
  retrieval    14
```

**3. Prove the suite can fail.**

A green suite tells you nothing unless you know it goes red when something breaks. Six realistic bugs are built into the agent behind an environment variable:

```bash
BUGS=retrieval_ignores_city python3 -m evals.runner
```

| Bug | What it models | Success rate | Blamed |
|---|---|---|---|
| `router_prefers_search` | Router checks search intent before policy intent | 92% | routing |
| `retrieval_ignores_city` | A filter silently dropped | 46% | retrieval |
| `retrieval_returns_everything` | Similarity threshold too loose | 35% | retrieval |
| `tool_rounds_wrong` | Truncation dressed up as rounding | 96% | tool_call |
| `tool_skips_booking` | Tool silently not invoked | 92% | tool_call |
| `generation_hallucinates_price` | A figure in no retrieved document | 50% | generation |

CI runs all six and **fails if any goes undetected**. Testing the tests.

---

## What the dataset looks like

26 hand-written cases. Small on purpose: a dataset you understand beats a large one you don't, and every case here exists because it can fail in a specific way.

```json
{
  "id": "policy-004",
  "group": "policy/routing-trap",
  "query": "Are pets allowed in a 2 bedroom flat in Seville?",
  "expect": {
    "intent": "policy",
    "doc_ids": ["P002"],
    "tools": [],
    "rubric": "Answers the pet policy question. The mention of a property is context, not a search request.",
    "judge_keywords": ["furnished", "approval"]
  }
}
```

That case exists because it's a trap: it contains every keyword a search router looks for, but it's a policy question. Cases are grouped (`search/grounding`, `policy/routing-trap`, `search/no-results`) so a failure *pattern* is visible instead of being averaged away.

---

## On LLM-as-judge

Judges are useful and not trustworthy. Known biases, and what's done about each here:

- **Position bias** — prefers whichever answer it sees first. *Mitigated:* score one answer against a fixed rubric rather than comparing two.
- **Verbosity bias** — longer answers score higher regardless of quality. *Mitigated:* the rubric names required content, and grounding is asserted separately, so padding can't buy a score.
- **Self-preference** — favours text from its own model family. *Not solved.* If it mattered, the judge should be a different family from the model under test.
- **Poor calibration** — scores drift between runs and versions. *Mitigated:* temperature 0, pinned model, and the score is used as a threshold rather than a metric to optimise.

Because of all that, **a failing judge score is a warning; a failing assertion fails the build.** A judge is a smoke alarm, not a specification.

Two implementations: `HeuristicJudge` (default, deterministic, offline, free — so CI runs without credentials) and `OpenAIJudge` (`JUDGE=openai`).

---

## Four bugs this found in its own agent

Worth being honest about, because they're the interesting part.

**1. An unrecognised city was silently dropped.** "Find a house in Bilbao" returned all eight listings across four other cities, because Bilbao wasn't in the known-city list so the filter was never applied. Silently ignoring a filter you can't honour is worse than returning nothing. *Fixed by applying unknown locations as filters anyway, so they correctly match nothing.*

**2. A booking tool fired on the wrong intent.** "Can I cancel a viewing?" *booked a viewing*, because the trigger keyed on the word "viewing" without checking intent. The word was present; the intent was the opposite.

**3. A booking fired on an empty result set.** "Book a viewing for a 5 bedroom flat in Seville" matched nothing — and booked a viewing anyway, with `listing_id: None`, so the answer read *"I couldn't find any properties matching those criteria. I've started a viewing request for you."* The tool check passed because it asserted which tools ran, not their arguments. *Fixed by requiring a non-empty result set, and the tool-result oracle now verifies the booked listing is one retrieval actually returned.*

**4. My own assertion had a false positive.** The forbidden-content check flagged the legitimate `1400 EUR` as containing the forbidden `400 EUR` — naive substring matching. Someone would have spent an afternoon debugging a hallucination that never happened. *Fixed with boundary-aware matching.*

And one gap in the suite itself: `tool_rounds_wrong` originally scored **100%** — undetected. I was asserting on *which* tools were called and never on *what they returned*. Fixed by recomputing tool outputs from the retrieved documents — an independent oracle, so it can't drift out of sync with the fixtures the way a hardcoded expected value would.

That last one is the reason `tests/test_harness.py` exists. An eval suite is test code, and test code nobody has tested is just code you trust for no reason.

---

## Layout

```
agent/          the system under test — 4 stages, traced, with seeded bugs
evals/
  dataset.json  26 curated cases
  assertions.py deterministic checks (intent, retrieval, tools, grounding)
  judge.py      LLM-as-judge + offline heuristic fallback
  runner.py     orchestration, stage attribution, reporting
tests/          tests for the harness itself
.github/        CI: run suite, verify it detects all 6 bugs, run unit tests
```

## Commands

```bash
python3 -m evals.runner                              # run the suite
python3 -m evals.runner --json reports/run.json      # machine-readable report
BUGS=generation_hallucinates_price python3 -m evals.runner
JUDGE=openai OPENAI_API_KEY=... python3 -m evals.runner
python3 -m pytest tests/ -v                          # test the harness
```

---

## What I'd do differently at scale

- **Semantic similarity for retrieval.** Exact ID matching works for a fixed corpus of eight documents. Real retrieval needs graded relevance rather than a set comparison.
- **More than one judge, and measure their agreement.** A single judge with no inter-rater agreement number is a number with unknown error bars.
- **Track score distribution over time, not just pass/fail.** A suite that stays green while scores drift downward is a suite about to break all at once.
- **Sample size and variance.** At temperature > 0, one run per case is a coin flip. Production evals need n runs per case and a confidence interval — 26 cases run once tells you about 26 samples, not about the system.
- **Adversarial cases.** Prompt injection, jailbreaks, PII leakage. The OWASP LLM Top 10 is the obvious starting list and there's nothing here yet.

---

Built by [Andrii Lutak](https://linkedin.com/in/andrii-lutak) — QA engineer, 7 years, most recently building the quality function and LLM evaluation for an AI product startup.
