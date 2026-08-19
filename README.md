# LLM evaluation harness

A regression suite for a conversational agent, plus a calibration suite for the
judge that grades it. Built the way I think LLM systems should be tested:
**assert everything you can, judge only what you can't, prove the judge, and
make failures point at the stage that broke.**

The eval suite runs in about a second with no API key, no install step and no
network. The calibration suite needs an OpenAI key and costs a few cents.

```bash
git clone <this-repo> && cd llm-eval-harness
python3 -m evals.runner
```

```
======================================================================
LLM EVALUATION REPORT
======================================================================
judge: heuristic   TEMP: 0.0   cases: 26 x 1 runs = 26 observations
stable pass: 26   FLAKY: 0   stable fail: 0   VACUOUS: 0

task success rate: 100.0%   95% CI [87.1%, 100.0%]
```

That confidence interval is the first thing worth noticing. 26 green tests do
not support a claim of high reliability, and the report says so rather than
printing a flattering 100%.

---

## The problem

You cannot test an LLM feature by asserting on the output string. The same
input produces different text every run, so exact assertions fail constantly
and get deleted. The usual response is to hand the whole answer to another
model and ask "is this good?", which produces a number that drifts between
runs, costs money, and tells you nothing about *where* the system went wrong.

Both approaches share a flaw: they treat the agent as one opaque box. It isn't.
It's a pipeline:

```
route  ->  retrieve  ->  tool_call  ->  generate
```

Three of those four stages are **completely deterministic**. Which intent was
chosen, which documents came back, which tools fired with which arguments —
none of that requires judgement. Only the final prose does.

---

## The approach

### 1. Assert everything deterministic

| Stage | How it's checked | Why |
|---|---|---|
| Routing | Exact intent match | It's a classification. Assert it. |
| Retrieval | Set comparison + precision/recall | Missing docs and extra docs are different bugs — reported separately |
| Tool calls | Which tools fired, **and what they returned** | Recomputed independently from the retrieved documents |
| Generation — facts | Every figure must trace to a retrieved document | Catches hallucination exactly, with no model |
| Generation — prose | LLM-as-judge against a rubric | The only part that genuinely needs judgement |

Judging what you could have asserted is how eval suites become slow, expensive
and vague.

### 2. A check has four possible verdicts, not two

```python
class Status(StrEnum):
    PASS  = "pass"
    FAIL  = "fail"
    NA    = "n/a"      # nothing to check — legitimately vacuous
    ERROR = "error"    # could not evaluate. Harness bug, not agent bug.
```

`NA` and `ERROR` exist because of a bug this suite had for a long time.
`check_grounding` extracted `(\d{3,5})\s*EUR` from the answer and returned
**PASS** when it found nothing — so the moment the model wrote `€1400` instead
of `1400 EUR`, the hallucination guard silently became a no-op and reported
success. Detection of a seeded hallucination fell from 100% to **23.5%** with
no test turning red.

> **An assertion that cannot evaluate its input must never report a pass.**
> Fail-open checks are worse than absent ones, because a suite full of them is
> green and confident.

`NA` is the honest answer when there is nothing to check. `ERROR` is the honest
answer when there is something to check and the harness cannot read it — a
defect in *my* code, so it blocks the build and is reported in its own section,
separately from agent failures. Confusing the two sends you debugging the wrong
codebase.

A case where **every** check returns `NA` is `VACUOUS`: it executed and
asserted nothing. That is not a pass.

### 3. Attribute every failure to the earliest broken stage

If retrieval returns the wrong documents, generation will also look wrong — but
the generator did its job faithfully with bad input. Reporting both is noise.
The runner blames the earliest failing stage, which turns *"the answer was
wrong"* into *"retrieval dropped the city filter"*.

### 4. Prove the suite can fail

Six realistic bugs are built into the agent behind an environment variable:

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

## Non-determinism

The agent above is deterministic keyword logic. That makes for a fast offline
suite and a dishonest one, because the defining property of an LLM feature is
that it does *not* do that. `agent/noise.py` injects the three kinds of
variation a real model introduces — paraphrase, routing flips on ambiguous
inputs, retrieval jitter — under a `TEMP` knob. `TEMP=0` is a hard no-op, so
the deterministic suite is bit-identical to before.

```bash
TEMP=0.3 python3 -m evals.runner --runs 20 --seed s1
```

```
stable pass: 9   FLAKY: 17   stable fail: 0   VACUOUS: 0
HARNESS ERRORS: 63 observations — see below.

task success rate: 85.8%   95% CI [82.5%, 88.5%]
per-run spread:    mean 85.8%   sd 6.8%   min 73.1%   max 100.0%
```

Three things that only appear once the system is stochastic:

**`FLAKY` is a first-class verdict.** 17 of 26 cases pass *sometimes*. Zero are
reliably broken. A single run reports each of them as either green or red and
both are lies — which is why "flaky" is a verdict rather than a re-run.

**Run-to-run spread is measured directly.** Same code, same dataset: CI would
have printed anything from 73.1% to 100.0%. That is the number that makes
people distrust an eval suite, and it is invisible from one run.

**Noise is not uniform.** Real systems fail on borderline inputs, so an
ambiguous query is ~17x likelier to be misrouted than a clear one. The variance
concentrates in specific strata, which is exactly why a single aggregate pass
rate is a bad summary — it averages a rock-stable group with a coin-flip group
and reports something true of neither.

---

## Statistics

- **Wilson score intervals**, not the textbook normal approximation. At 26/26
  the naive formula gives `[1.0, 1.0]` — "we are certain this system never
  fails", from 26 observations. Wilson gives `[0.87, 1.00]`.
- **Per-stratum rates with their own intervals.** 13 groups, so a failure
  *pattern* is visible instead of averaged away.
- **N/A rate per check**, because coverage can vanish silently. Turning on the
  four-state model immediately revealed that 47 of 156 check-results were
  vacuous passes — **30% of the green was nothing at all**. Most of that is
  `check_forbidden` on cases with no forbidden list defined, which is a gap in
  the *dataset*, now measurable.
- **CI gate modes:** `--gate strict`, or `--gate lower-bound --min-rate 0.95`
  which gates on the interval's lower bound. Note that a lower-bound gate is
  sensitive to `--runs`: the interval narrows as n grows, so the run count is
  part of the gate's definition, not an implementation detail.

---

## Judge calibration

An LLM-as-judge is an instrument. Instruments get calibrated, and until they
are, a judge score is an opinion with a number attached.

`evals/variants.py` degrades a real agent answer in controlled ways, each
carrying a ground-truth score:

| variant | truth | defect |
|---|---|---|
| `original` | 5 | none |
| `padded` | 4 | 3x longer, no new content |
| `hedged` | 4 | drowned in qualifiers |
| `omission` | 2 | a fact the case rubric *names* is removed |
| `wrong` | 1 | a figure corrupted; same length, still fluent |
| `verbose_wrong` | 1 | long, fluent, confident **and** false |

You then label them blind (`python3 -m evals.label`), and
`python3 -m evals.calibration` compares three sources — ground truth, human
labels, and the judge — across four judge configurations that differ by one
variable at a time.

### Every degradation carries a witness

A variant is only emitted if a predicate confirms it genuinely exhibits the
defect its score claims; otherwise it is skipped. This exists because the
reference standard was wrong twice, and the second one was subtle:

1. `_wrong` had nothing to corrupt in a no-results answer, returned the input
   unchanged, and the item was labelled `truth=1`. A perfect answer scored 1.
2. `_omit` removed the average-price sentence — which **no rubric requires**.
   Every judge scored it 5/5 and was right to; the reference was wrong. A
   difference check could not catch this, because the answers genuinely
   differed.

> **A defect that cannot be detected from what the rater was told is not a
> defect — it is an unstated preference.**

The first validator compared each variant to its original and caught 2 bad
items. The witness version asks whether the variant *exhibits the defect its
score claims* and catches 7 on the same data. Sameness was a proxy for the
property that actually mattered.

### Findings

From a clean run: 36 items, 4 judges, 3 repeats, 324 fresh API calls, no cache
reuse, `corr(length, truth) = -0.07`.

```
vs GROUND TRUTH        exact  within 1   kappa   wtd kappa    MAE
  human                 78%      81%      0.70     0.52       0.69
  heuristic             22%      72%      0.12     0.58       1.11
  openai-vague          33%      72%      0.19     0.32       1.19
  openai-anchored       42%      72%      0.27     0.33       1.05
  openai-context        67%      89%      0.55     0.86       0.33
```

**Context is the whole ballgame.** Same model, same rubric, same answers — the
only difference is the retrieved documents in the prompt. Detection of the
`wrong` variant: 1.17 against a truth of 1.00, versus 3.33 for every
document-free configuration. **A rater without the source material cannot
detect a hallucination; a rater with it detects it almost perfectly.** This is
why grounding lives in `assertions.py` and not in the judge.

**Human agreement selects the wrong judge.**

```
                  vs TRUTH (wtd)   vs HUMAN (wtd)
openai-vague          0.32             0.62
openai-anchored       0.33             0.70
openai-context        0.86             0.53   <- best vs truth, worst vs human
```

Replicated across three runs on three different reference datasets. Ranking
judges by agreement with human labels reliably picks the one that shares the
humans' blind spot — and "does it agree with our raters?" is the industry's
default acceptance criterion.

**Exact agreement and weighted kappa rank raters in opposite orders.** The
human beats `openai-context` on exact agreement (78% vs 67%) and loses badly on
weighted kappa (0.52 vs 0.86), because the human is perfect on four categories
and two full points out on both truth=1 categories. On an ordinal scale, exact
agreement is the flattering number.

**Rubric anchoring buys targeting and stability, not accuracy.** It moves
omission detection a full point (3.83 → 2.83) — the anchor literally says "2 =
a required fact is missing", and absence is invisible unless you're told to
look for it — and it is the only configuration at 100% self-consistency in
every run. Overall accuracy barely moves.

**Verbosity bias: none, in the OpenAI judges.** All three sit at the
`corr(length, truth)` baseline. Two earlier runs "found" verbosity bias in
opposite directions; both were artifacts of a dataset where length predicted
quality. A bias probe is worthless until you have shown the dataset does not
produce that bias on its own.

### Measurement hygiene

- **Judge calls are cached to disk**, keyed by `(tag, model, judge, prompt,
  attempt)`. The attempt number matters: cache on the prompt alone and
  `--repeat 3` serves repeats 2 and 3 from repeat 1, so self-consistency reads
  100% by construction — a property of the cache reported as a property of the
  model.
- **`--tag` namespaces an experiment.** A cache spanning several days silently
  mixes model vintages, and whichever judge you ran first is the one with stale
  data. A new tag re-measures everything while staying resumable.
- **A missing judge is fatal by default.** If a requested configuration cannot
  start, the run exits non-zero and prints no tables. A comparison missing half
  its conditions that *looks* complete is how a broken experiment gets quoted.
- **Stale labels are detected.** `labels.json` written before a change to
  `variants.py` is well-formed, internally consistent, and the wrong dataset.

---

## Layout

```
agent/
  agent.py       the system under test — 4 stages, traced, 6 seeded bugs
  noise.py       controlled non-determinism (TEMP)
evals/
  dataset.json   26 curated cases in 13 strata
  assertions.py  deterministic checks; Status vocabulary
  extract.py     loose detector + strict parser for money
  judge.py       heuristic + 3 OpenAI configurations, cached
  runner.py      orchestration, attribution, statistics, reporting
  variants.py    degradations with witnesses
  label.py       blind labelling CLI with content-based label migration
  calibration.py judge vs human vs truth
  rubric.py      the 1-5 scale — one definition, two consumers
tests/           tests for the harness itself (51 passing)
```

## Commands

```bash
python3 -m evals.runner                                  # run the suite
TEMP=0.3 python3 -m evals.runner --runs 20 --seed s1     # stochastic, with variance
BUGS=generation_hallucinates_price python3 -m evals.runner
python3 -m evals.runner --gate lower-bound --min-rate 0.95
python3 -m pytest tests/ -v                              # test the harness

python3 -m evals.label                                   # label blind
python3 -m evals.calibration --judges heuristic,openai-vague,openai-anchored,openai-context \
                             --repeat 3 --tag run1
```

---

## What I'd do differently at scale

- **Semantic similarity for retrieval.** Exact ID matching works for eight
  documents. Real retrieval needs graded relevance.
- **More than one human rater.** Everything here is calibrated to one person's
  taste, so there is no inter-rater agreement to compute and the kappas have
  wide intervals at n=36.
- **A stored baseline for gating.** Absolute per-stratum floors are brittle;
  regression against a baseline catches change but ratchets in existing
  badness. Real setups need both.
- **Extend the four-state model to more checks.** `ERROR` currently has one
  producer. Every parser in the suite deserves one.
- **Adversarial cases.** Prompt injection, jailbreaks, PII leakage. The OWASP
  LLM Top 10 is the obvious starting list and there is nothing here yet.

---

Built by [Andrii Lutak](https://linkedin.com/in/andrii-lutak) — QA engineer, 7 years, most recently building the quality function and LLM evaluation for an AI product startup.
