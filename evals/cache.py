"""On-disk cache for judge calls.

Judge calls cost money, are rate limited, and are slow. Without a cache, an
eval run has three bad properties:

  * a failure halfway through discards every call that already succeeded
  * re-running to change one thing pays for everything again
  * a daily rate limit makes a run larger than the limit simply impossible

All three are fixed by remembering answers on disk. A run that dies at call 50
resumes at call 51 tomorrow, and the first 50 are free.

THE KEY MUST INCLUDE AN ATTEMPT NUMBER.
The obvious cache key is (model, prompt). That is wrong here, and wrong in a
way that would quietly destroy a measurement: `--repeat 3` sends the SAME
prompt three times specifically to see whether the judge answers consistently.
Cache on the prompt alone and repeats 2 and 3 are served from repeat 1, so
self-consistency reads 100% by construction — the harness would be reporting
a property of the cache as a property of the model.

So the key is (model, judge, prompt, attempt). Repeat i is cached separately
from repeat j. Resuming is safe; the variance measurement survives.
"""

import hashlib
import json
import os
import time

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".judge_cache.json")


class Cache:
    def __init__(self, path=DEFAULT_PATH, enabled=True):
        self.path = path
        self.enabled = enabled
        self.data = {}
        self.hits = 0
        self.misses = 0
        self.hit_ages = []          # vintages of served entries, for the report
        if enabled and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self.data = {}          # a corrupt cache is not worth a crash

    @staticmethod
    def key(model, judge_name, prompt, attempt, tag="v1"):
        """`tag` namespaces a whole experiment.

        A cache spanning several days silently mixes model VINTAGES: the
        provider can change what sits behind a model id at any time, so
        Tuesday's cached score and Thursday's fresh one were not necessarily
        produced by the same thing. That is invisible and it biases a
        comparison across configurations, because whichever judge you ran
        first is the one with the old data.

        Bumping the tag gives a clean namespace: every call misses, every
        result is written, and a run that dies halfway still resumes WITHIN
        that tag. Fresh measurement and resumability are not in tension.
        """
        raw = f"{tag}\x00{model}\x00{judge_name}\x00{attempt}\x00{prompt}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, k):
        if not self.enabled:
            return None
        hit = self.data.get(k)
        if hit is None:
            self.misses += 1
        else:
            self.hits += 1
            if isinstance(hit, dict) and hit.get("ts"):
                self.hit_ages.append(hit["ts"])
        return hit

    def set(self, k, value):
        if not self.enabled:
            return
        self.data[k] = value
        self.flush()                    # write through: a crash loses nothing

    def flush(self):
        if not self.enabled:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)      # atomic; never leaves a half-written file

    def stats(self):
        """Report vintage, not just counts.

        "207 cached" sounds like thrift. "207 cached, oldest 2 days old" tells
        you the report mixes measurements taken under conditions that may have
        differed — which is the thing you actually need to know.
        """
        base = f"{self.hits} cached, {self.misses} fetched"
        if not self.hit_ages:
            return base
        now = time.time()
        oldest = (now - min(self.hit_ages)) / 3600
        newest = (now - max(self.hit_ages)) / 3600
        span = f"{newest:.0f}-{oldest:.0f}h old" if oldest - newest > 1 else f"{oldest:.0f}h old"
        return f"{base} (served entries {span})"
