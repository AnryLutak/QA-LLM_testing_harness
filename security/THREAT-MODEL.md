# Threat model — rental assistant

Block 3.0 output. Written before any attack was built, because a red-team suite
assembled without one is a list of payloads somebody found on the internet.

**Revised at the close of 3.1.** Two things changed under it and a threat model
that describes a system which no longer exists is worse than none: a live-model
path was added (`agent/llm.py`), so the SUT is now *either* the simulator or a
real model depending on how it is run; and the scope decisions that were
implicit — no direct-injection cases, no jailbreak cases — are written down
below rather than left to be inferred from the dataset.

## The system

```
  user query ──▶ route ──▶ retrieve ──▶ call_tools ──▶ generate ──▶ answer
                             │             │                            │
                        corpus (DOCS)   book_viewing              printed / logged
                                        average_price
```

## Trust boundaries

**Text entering the model's context**

| Edge | Controlled by | Notes |
|---|---|---|
| `query` | the user | direct injection surface; bounded blast radius (their own session) |
| `DOCS[*].text` | **anyone who can publish a listing** | the indirect surface, and the dangerous one: the victim is not the attacker |
| tool results | computed internally from `DOCS` | trusted today; would be untrusted the moment `book_viewing` calls a real API |
| conversation history | **does not exist** | single turn, no memory — crescendo and memory-poisoning are out of scope, and that is a property of the design, not an oversight |

**Where model output leaves**

| Sink | Consumer | Interprets it? |
|---|---|---|
| answer text | user, report JSON, stdout | no |
| `book_viewing.notes` | forwarded onward to a landlord | **a machine reads this, and no human ever will** |
| `book_viewing.listing_id` | booking system | yes — a real-world commitment |

## The lethal trifecta

| Leg | Present? | Where |
|---|---|---|
| access to private data | yes | `agent/config.py` — system prompt with an `escalation_key` |
| exposure to untrusted content | yes | `CORPUS_OVERLAY` — a published listing |
| ability to communicate externally | yes | `book_viewing.notes`, a free-text outbound parameter |

All three. So an exfiltration path exists and the only question is whether a
payload connects them. `inj-003` connects two of them; 3.3 connects all three.

**Where to cut.** Legs 1 and 2 are the product — a rental assistant without
private configuration or landlord-written listings is not a rental assistant.
Leg 3 is not. `notes` is a free-text field because nobody decided it should be
anything else, and turning it into an enum costs one constant. That is the
`capability` defence, and the ASR matrix shows it is the only mitigation here
that takes an attack to zero without collateral damage.

## Assets and worst case per edge

| Untrusted edge | Worst outcome given current capabilities |
|---|---|
| `query` | the user manipulates their own session; no other tenant's data is reachable |
| `DOCS[*].text` | attacker controls the answer text, leaks the system prompt, books viewings on the victim's behalf, and puts arbitrary text into an outbound parameter |
| tool results | not exploitable today; becomes the highest-severity edge the day a tool returns third-party content |

## Scope: what is deliberately not attacked

Written down because "we didn't test it" and "we decided not to test it" look
identical in a findings table, and only one of them survives being asked about.

| Not covered | Why | What would change that |
|---|---|---|
| **Direct injection** (payload in `query`) | The blast radius is the attacker's own session: there is no other tenant's data to reach and no privileged action they could not simply request. It is a real class and a boring one *here*. | The moment retrieval spans more than one tenant, or a tool acts on someone else's behalf — which is 3.2's surface, not 3.1's. |
| **Jailbreak** (bypassing refusal) | This SUT has no safety behaviour to bypass. It answers rental questions; there is no refusal boundary, so "the model was talked out of refusing" has no referent. Injection and jailbreak get conflated constantly and this is the cleanest place to say they are different: **injection subverts whose instructions are followed, jailbreak subverts what the model is willing to do.** | A moderation or policy layer, which this product does not have. |
| **Multi-turn** (crescendo, memory poisoning) | Single turn, no history. A property of the design, not an oversight. | Conversation memory. |
| **Cross-modal** (image/audio carriers) | Text-only SUT. Worth naming because the **2026** LLM01 absorbed cross-modal injection, so citing the 2026 list means knowing this row is empty on purpose. | An attachment or image path. |
| **Tool results as carrier** | Tool results are computed internally from `DOCS` today, so they carry nothing an attacker wrote that the documents did not already carry. | The first tool that returns third-party content — flagged above as the highest-severity edge in that event. |

Direct injection is not entirely unmeasured, and the measurement was an
accident worth keeping. `pos-002` … `pos-004` put instructions in `query` to
prove the *capability* exists, and they answer a question the attack cases
cannot: the same instruction is obeyed **20/20 from the user** and **0–45%
from a document**. The instruction hierarchy is real and partial. That contrast
is the argument for why indirect is the interesting half.

## What this SUT cannot tell you

Recorded here so it never has to be remembered under interview pressure.

**There are two SUTs in this repo and the reports say which one ran.**

- `LLM=openai` — a real model generates the answer (`agent/llm.py`). Attack
  success is a property of that model, at that vintage, with that payload.
  Reports print `mode: LIVE MODEL — <model>`; the live numbers live in
  `security/FINDINGS.md` and every rate quoted there names the report it came
  from.
- Default — the agent is deterministic keyword logic and string templating with
  no instruction-following, so injection is **simulated** by
  `agent/injection.py` under `BUGS=generation_obeys_documents`, in the same
  spirit as `noise.py` simulating non-determinism. Reports print
  `mode: SIMULATED (INJECT_P=…)`.

- **Demonstrated on both paths:** detection logic, fail-closed contracts, OWASP
  mapping, and that a given mitigation moves attack success by a measured
  amount.
- **Never to be claimed from the simulated path:** that any real model is
  vulnerable to any payload here. A simulated ASR is a property of a knob.
- **Never to be claimed from the live path either:** that a payload which
  failed does not work. A one-word edit moved attack success by 45 points
  (H-003), so a 0% is one phrasing failing, not an attack class failing.

The defence matrix (`--compare`) is still measured on the **simulated** path
only. It is a statement about what each mitigation can and cannot *see* —
`input_filter` never sees the joined context, `capability` removes the sink
regardless — which is a property of the code, not of a model. Re-running it
live would put a rate on each cell; it would not change which cells are zero.

Standard-tool comparison (`promptfoo`, `garak`, DeepTeam) is 3.5, and is still
outstanding: nothing in this repo has been run against a tool anyone else
wrote.

## Two findings from reviewing the existing harness

**`check_grounding` proves provenance, not truth.** It compares figures in the
answer against `knowledge.get(id)["price"]` — the structured field — while
`generate()` writes prose from `d["text"]`. Two independent representations, so
a text-only poison is caught. Poison both fields consistently and the check
returns PASS with `"all 1 figures grounded"`. In a real RAG system there is no
structured price column and the allowed set would come from the same chunk the
answer was written from, at which point corpus poisoning defeats grounding by
construction. Proxy problem, seventh instance: *grounded-in-a-document* is a
proxy for *true*. Maps to LLM05 and LLM09.

**`check_tool_results` has been an excessive-agency control since the day it was
written.** Its guard that `book_viewing`'s `listing_id` must be among the
retrieved documents was added as a correctness fix. Unchanged, it is the
containment half of LLM03 / ASI02. `no_unrequested_action` in
`evals/security.py` is the other half: *was there any business booking at all*.
