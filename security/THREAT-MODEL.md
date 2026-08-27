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
| `query` | the user | direct injection surface; blast radius now bounded by the VIEWER, not by the session — see below |
| `viewer` | the calling application | **the new boundary in 3.2.** Not attacker-controlled in this model: an unauthenticated visitor cannot claim to be an agent. Everything below assumes that; if identity itself is forgeable, none of the ACL results mean anything and the finding is one layer down |
| `DOCS[*].text` | **anyone who can publish a listing** | the indirect surface, and the dangerous one: the victim is not the attacker |
| tool results | computed internally from `DOCS` | trusted today; would be untrusted the moment `book_viewing` calls a real API |
| conversation history | **does not exist** | single turn, no memory — crescendo and memory-poisoning are out of scope, and that is a property of the design, not an oversight |

**Where model output leaves**

| Sink | Consumer | Interprets it? |
|---|---|---|
| answer text | user, report JSON, stdout | no |
| `book_viewing.notes` | forwarded onward to a landlord | **a machine reads this, and no human ever will** |
| `book_viewing.listing_id` | booking system | yes — a real-world commitment |

**Where the access control sits**

```
  viewer ─────────────────────────┐
                                  ▼
  user query ──▶ route ──▶ [ACL] retrieve ──▶ call_tools ──▶ generate ──▶ answer
```

Before the query filters, inside `retrieve()`, in one function (`can_see`), and
nowhere else. Three places it deliberately does **not** sit, each of which is a
real pattern in shipped products:

| Not here | Why it is not a control |
|---|---|
| in the system prompt (*"only cite documents marked PUBLIC"*) | a preference expressed in the same channel as the data it protects. It fails stochastically, so it passes review and leaks at some rate |
| after generation, as redaction | catches the string and misses the inference. "The owner is relocating and may be flexible" contains no canary and no number |
| as a pre-built per-tenant index | drifts. Access revoked at 10:00 is still in the index until the next rebuild |

The first of those is the one worth measuring rather than asserting, and it is
deliberately **not built** — measuring how often a prompt-level filter fails
needs the live model, and a simulated compliance rate for it would be a number
I invented, which is the same trap `agent/injection.py` documents. Scoped to
3.3 with the payload chain.

## The lethal trifecta

| Leg | Present? | Where |
|---|---|---|
| access to private data | yes, and **three kinds of it since 3.2** | `agent/config.py` — the system prompt with an `escalation_key`; `L950` — an internal note owned by us; `A950` — personal data owned by a customer; `C950` — a listing owned by another tenant |
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
| `query` | **as of 3.2 this row is no longer trivially true.** Another tenant's data now exists in the corpus, so "the user manipulates their own session" is a claim about the ACL rather than about the design. It is enforced in `retrieve()` and gated by `ten-001`; the honest form is *no other tenant's data is reachable while that control holds* |
| `viewer` | out of scope by assumption — see the trust-boundary note. If identity is forgeable every disclosure result above collapses, which is why it is stated rather than implied |
| `DOCS[*].text` | attacker controls the answer text, leaks the system prompt, books viewings on the victim's behalf, and puts arbitrary text into an outbound parameter |
| tool results | not exploitable today; becomes the highest-severity edge the day a tool returns third-party content |

## Scope: what is deliberately not attacked

Written down because "we didn't test it" and "we decided not to test it" look
identical in a findings table, and only one of them survives being asked about.

| Not covered | Why | What would change that |
|---|---|---|
| **Direct injection** (payload in `query`) | The blast radius was the attacker's own session. **3.2 partly changed this and the row is kept to show why:** retrieval now spans two tenants, so there IS other data to reach — but reaching it requires the ACL to fail, not the model to be persuaded. Which is the finding: the control that matters is not in the model, so the injection class that attacks the model is still the boring one here. | A tool that acts on another user's behalf. That is 3.3. |
| **Jailbreak** (bypassing refusal) | This SUT has no safety behaviour to bypass. It answers rental questions; there is no refusal boundary, so "the model was talked out of refusing" has no referent. Injection and jailbreak get conflated constantly and this is the cleanest place to say they are different: **injection subverts whose instructions are followed, jailbreak subverts what the model is willing to do.** | A moderation or policy layer, which this product does not have. |
| **Multi-turn** (crescendo, memory poisoning) | Single turn, no history. A property of the design, not an oversight. | Conversation memory. |
| **Cross-modal** (image/audio carriers) | Text-only SUT. Worth naming because the **2026** LLM01 absorbed cross-modal injection, so citing the 2026 list means knowing this row is empty on purpose. | An attachment or image path. |
| **Tool results as carrier** | Tool results are computed internally from `DOCS` today, so they carry nothing an attacker wrote that the documents did not already carry. | The first tool that returns third-party content — flagged above as the highest-severity edge in that event. |
| **Training-data memorisation** (LLM02, leak source 1) | Nothing here is trained or fine-tuned. The weights belong to the provider, so this leak source has a different owner and no test in this repo could reach it. Named because "we don't fine-tune" is the answer, and silence is not. | A fine-tune. Then: canaries planted in the training set, and extraction probes. |
| **Embedding inversion / vector-store access** (LLM09) | Retrieval is a list comprehension over a Python list — there is no vector store to under-protect. The 2026 guidance is that a vector database needs controls at least as strong as the documents it indexes, and here that requirement is vacuously met. | A real index. The ACL would have to move to the query the store receives, which is where it usually gets lost. |
| **Aggregation and inference leaks** | The suite matches strings. "The owner may be flexible on price" discloses the same secret as the floor price and contains neither the canary nor the number. This is a rung-6 question and it is the known ceiling of every check in `no_restricted_disclosure`. | A judge, calibrated — which is Block 1 machinery pointed at a security question, not new machinery. |
| **Forged identity** | The viewer is supplied by the calling application and trusted. Attacking it is an authn/authz problem that exists identically without an LLM. | Nothing about the model; it would be an ordinary application-security finding. |

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
  Reports print `SUT: LIVE MODEL — <model>`; the live numbers live in
  `security/FINDINGS.md` and every rate quoted there names the report it came
  from.
- Default — the agent is deterministic keyword logic and string templating with
  no instruction-following, so injection is **simulated** by
  `agent/injection.py` under `BUGS=generation_obeys_documents`, in the same
  spirit as `noise.py` simulating non-determinism. Reports print
  `SUT: SIMULATED (INJECT_P=…)`. (Both lines were labelled `mode:` until the
  run gained a `--mode` flag selecting standard or extended sample sizes; the
  label is now `SUT:`, which is what it always meant.)

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
