"""
dga_classifier.py — offline, explainable DGA classifier (inference).

Why ML here (and nowhere else by default): the statistical DGA heuristic in
`dns_analysis.py` keys on Shannon entropy + NXDOMAIN ratio. That catches
*random-looking* DGAs (Conficker, Cryptolocker) but structurally MISSES
*dictionary* DGAs (suppobox, matsnu, gozi, rovnix) — they concatenate real
words, so entropy stays in the benign range and the threshold never trips. A
small character-n-gram logistic-regression model learns the bigram/trigram
structure that separates word-salad DGAs from real registrable names, which is
the one place a learned model beats hand-set thresholds on real recall.

Design constraints (court-admissible, air-gapped):
  * The shipped model is a HUMAN-READABLE JSON of weights — no pickle (no
    arbitrary-code-on-load), no runtime ML dependency. You can audit every
    coefficient.
  * Inference is pure Python and deterministic.
  * Every verdict is explainable: `score()` returns the top n-grams that drove
    it, so a report can say *why*, not just "the model said so".
  * It augments, never replaces, the explainable heuristic; an ML-only hit is a
    candidate for the analyst, never an assertion.

Feature extraction here is the single source of truth — the trainer
(`tools/train_dga_classifier.py`) imports it, so train/inference cannot drift.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import Counter
import json
import math
import os

_DEFAULT_MODEL = os.path.join(
    os.path.dirname(__file__), "..", "data", "models", "dga_lr.json")

_VOWELS = set("aeiou")


def char_ngrams(s: str, ns=(2, 3)) -> list[str]:
    """Boundary-marked character n-grams. '^'/'$' capture start/end structure
    (DGAs have unusual openings/closings vs. real names)."""
    s = "^" + s + "$"
    out = []
    for n in ns:
        for i in range(len(s) - n + 1):
            out.append(s[i:i + n])
    return out


def featurize(sld: str) -> dict[str, float]:
    """Map a second-level label to a {feature_name: value} dict.

    n-gram features are length-normalised counts (so the model learns structure,
    not merely length); a handful of named scalar features add interpretable
    linguistic signal. All values sit in ~[0,1] so no scaler needs shipping.
    """
    sld = (sld or "").lower()
    feats: dict[str, float] = {}
    if not sld:
        return feats
    grams = char_ngrams(sld)
    denom = max(len(grams), 1)
    for g, c in Counter(grams).items():
        feats["ng:" + g] = c / denom

    n = len(sld)
    vowels = sum(1 for ch in sld if ch in _VOWELS)
    digits = sum(1 for ch in sld if ch.isdigit())
    # longest consonant run (DGAs pack consonants; real words rarely do)
    run = best = 0
    for ch in sld:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1; best = max(best, run)
        else:
            run = 0
    counts = Counter(sld)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())

    feats["f:len"] = min(n, 30) / 30.0
    feats["f:vowel_ratio"] = vowels / n
    feats["f:digit_ratio"] = digits / n
    feats["f:max_consonant_run"] = min(best, 10) / 10.0
    feats["f:entropy"] = min(entropy, 5.0) / 5.0
    return feats


def _sigmoid(x: float) -> float:
    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


@dataclass
class DGAScore:
    is_dga: bool
    probability: float
    top_features: list          # [(feature, signed_contribution), ...] most positive
    threshold: float


class DGAModel:
    """Loads the JSON weight vector and scores second-level labels."""

    def __init__(self, vocab: dict, weights: list, bias: float,
                 threshold: float = 0.5, meta: dict | None = None):
        self.vocab = vocab
        self.weights = weights
        self.bias = bias
        self.threshold = threshold
        self.meta = meta or {}

    @classmethod
    def load(cls, path: str = _DEFAULT_MODEL) -> "DGAModel":
        with open(path) as f:
            m = json.load(f)
        return cls(m["vocab"], m["weights"], m["bias"],
                   m.get("threshold", 0.5), m.get("meta", {}))

    def score(self, sld: str, top_k: int = 6) -> DGAScore:
        feats = featurize(sld)
        z = self.bias
        contribs = []
        for name, val in feats.items():
            idx = self.vocab.get(name)
            if idx is None:
                continue
            c = self.weights[idx] * val
            z += c
            if c != 0:
                contribs.append((name, round(c, 4)))
        prob = _sigmoid(z)
        contribs.sort(key=lambda t: t[1], reverse=True)
        return DGAScore(prob >= self.threshold, round(prob, 4),
                        contribs[:top_k], self.threshold)


_CACHE: DGAModel | None = None


def get_model(path: str = _DEFAULT_MODEL) -> DGAModel | None:
    """Cached default model; returns None if the artifact isn't present so the
    pipeline degrades gracefully to the heuristic (never a hard dependency)."""
    global _CACHE
    if _CACHE is None:
        if not os.path.exists(path):
            return None
        _CACHE = DGAModel.load(path)
    return _CACHE
