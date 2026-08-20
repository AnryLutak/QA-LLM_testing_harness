# Threat model — rental assistant

Block 3.0 output. Written before any attack was built, because a red-team suite
assembled without one is a list of payloads somebody found on the internet.

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

## What this SUT cannot tell you

Recorded here so it never has to be remembered under interview pressure.

The agent is deterministic keyword logic and string templating. It has no
instruction-following, so indirect prompt injection is **simulated** by
`agent/injection.py` under `BUGS=generation_obeys_documents`, in the same
spirit as `noise.py` simulating non-determinism and `BUGS` simulating defects.

- **Demonstrated:** detection logic, fail-closed contracts, OWASP mapping,
  and that a given mitigation moves attack success by a measured amount.
- **Not demonstrated, and never to be claimed:** that any real model is
  vulnerable to any payload here. Every ASR in `reports/redteam.json` is a
  property of the simulator's compliance knob.

Real-model attack success is measured separately in 3.5 by pointing
`promptfoo redteam` at a live endpoint. The two live in different sections of
the README on purpose.

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
