# Calibration runs

Kept in version control although they are generated output, because they
cannot be regenerated. Each is a measurement of a specific model version on a
specific date, and the provider moves what sits behind a model id without
notice — `gpt-4o-mini` next quarter is not the `gpt-4o-mini` measured here.

A number without its date and model is not evidence, it is a claim.

| run | date | judge model | dataset | what changed | headline |
|---|---|---|---|---|---|
| `run1.txt` | 2026-08-18 | gpt-4o-mini | 28 of 30 items usable | first pass | context judge wtd kappa 0.52; two reference items rejected |
| `run2.txt` | 2026-08-18 | gpt-4o-mini | 30 of 30 | `omission` retargeted at a required keyword; `wrong` fabricates for no-results | human kappa 0.37 -> 0.58 on the SAME labels — the reference had been wrong, not the rater |
| `run3.txt` | 2026-08-19 | gpt-4o-mini | 36 of 36 | `hedged` rescored to 4; `verbose_wrong` added to break the length confound; fresh `--tag`, no cache reuse | context wtd kappa **0.86** vs 0.32-0.33 without documents |

## The arc, in one paragraph

Run 1 concluded that judges are blind to omission. Run 2 showed that
conclusion was an artifact of a broken reference standard: nothing in the
dataset ever required the fact being removed, so every judge was right and the
ground truth was wrong. Run 3, on a corrected and confound-balanced dataset,
produced the finding that survives — a judge given the retrieved documents
detects hallucination almost perfectly, and one without them cannot detect it
at all.

Two conclusions were retracted along the way. Both retractions are more
instructive than the results that replaced them, which is why all three runs
are kept rather than only the last.

## Reproducing (approximately)

```bash
python3 -m evals.calibration \
  --judges heuristic,openai-vague,openai-anchored,openai-context \
  --repeat 3 --tag <new-tag>
```

Approximately, because the model behind the id will have moved. Expect the
direction of every finding to hold and the exact numbers not to.
