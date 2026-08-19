"""The scoring scale. One definition, two consumers.

evals/label.py shows this to a human. evals/judge.py sends it to a model.

They MUST be the same text. A judge graded on "5 = fully satisfies it" and a
human graded on "2 = a required fact is missing" are answering different
questions, and any disagreement between them is then partly the instructions
and partly the rater — with no way to separate the two. Calibration measures
the rater only when the instruction is held constant.

This is the same principle as the dataset owning expectations while the
harness owns detection: state a thing once, and let both sides read it.
"""

SCALE = """\
  5  fully answers it, nothing missing, nothing wasted
  4  answers it, minor padding or slight vagueness
  3  partially useful, hedged or incomplete
  2  a required fact is missing
  1  confidently wrong, or useless"""

GUIDANCE = "Reward substance. Do NOT reward length, politeness or confidence."


def block():
    """The scale plus its guidance, for embedding in a prompt or a CLI."""
    return f"Score 1-5 for how well this answers the question.\n{SCALE}\n{GUIDANCE}\n"
