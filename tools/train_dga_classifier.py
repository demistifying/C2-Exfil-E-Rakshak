"""
train_dga_classifier.py — offline trainer for the DGA logistic-regression model.

Produces data/models/dga_lr.json (auditable JSON weights) consumed by
pipeline/dga_classifier.py. Run offline / at dev time only; inference ships with
no ML dependency.

Labeled data provenance (all offline, reproducible with the fixed seed):
  NEGATIVES (label 0, "not DGA")
    * real second-level domains        — data/models/benign_domains.txt (curated)
    * real English words               — data/models/dga_wordlist_en.txt
      (single real words look like legitimately registrable names)
  POSITIVES (label 1, "DGA")
    * random-character families        — faithful to Conficker / Cryptolocker /
      Necurs (high-entropy alnum salad)
    * dictionary-concatenation families — faithful to suppobox / matsnu / gozi /
      rovnix (real words glued together; LOW entropy — the class the heuristic
      misses and the reason this model exists)

The DGA generators reproduce the *structure* of published algorithms, not any
single botnet's seed, so the model learns general DGA morphology. Swap in real
labeled feeds (Netlab360 / Bambenek / DGArchive) and re-run to harden further;
the pipeline and tests are agnostic to how the JSON was produced.

Usage:  python3 tools/train_dga_classifier.py
"""

from __future__ import annotations
import json
import os
import random
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from dga_classifier import featurize  # single source of truth for features

ROOT = os.path.join(os.path.dirname(__file__), "..")
MODELS = os.path.join(ROOT, "data", "models")
SEED = 1337

# consonant-heavy alphabet weighting reused by a couple of families
_ALPHA = "abcdefghijklmnopqrstuvwxyz"
_ALNUM = _ALPHA + "0123456789"


# ---------------------------------------------------------------- data sources
def load_words() -> list[str]:
    p = os.path.join(MODELS, "dga_wordlist_en.txt")
    return [w.strip() for w in open(p) if w.strip() and not w.startswith("#")]


def load_benign_domains() -> list[str]:
    p = os.path.join(MODELS, "benign_domains.txt")
    return [w.strip().lower() for w in open(p)
            if w.strip() and not w.startswith("#")]


# ------------------------------------------------------------- DGA generators
def gen_random(rng: random.Random, n: int) -> list[str]:
    """Conficker/Cryptolocker-style: random letters, length 7-15."""
    out = []
    for _ in range(n):
        L = rng.randint(7, 15)
        out.append("".join(rng.choice(_ALPHA) for _ in range(L)))
    return out


def gen_random_alnum(rng: random.Random, n: int) -> list[str]:
    """Necurs/Ramnit-style: mixed letters+digits, length 8-20."""
    out = []
    for _ in range(n):
        L = rng.randint(8, 20)
        out.append("".join(rng.choice(_ALNUM) for _ in range(L)))
    return out


def gen_dictionary(rng: random.Random, words: list[str], n: int) -> list[str]:
    """suppobox/matsnu/gozi-style: concatenate 2-3 real words (low entropy)."""
    short = [w for w in words if 3 <= len(w) <= 8]
    out = []
    for _ in range(n):
        k = rng.choice([2, 2, 2, 3])            # mostly 2-word, some 3-word
        out.append("".join(rng.choice(short) for _ in range(k)))
    return out


def build_dataset():
    rng = random.Random(SEED)
    words = load_words()
    benign_domains = load_benign_domains()

    # --- negatives ---
    neg = list(benign_domains)
    # real single words as additional benign-registrable examples
    neg += rng.sample(words, min(12000, len(words)))
    neg = list(dict.fromkeys(neg))              # dedupe, keep order

    # --- positives (balanced across families, ~ matched to negative count) ---
    target = len(neg)
    per = target // 3
    pos = (gen_random(rng, per)
           + gen_random_alnum(rng, per)
           + gen_dictionary(rng, words, target - 2 * per))

    X = [(s, 0) for s in neg] + [(s, 1) for s in pos]
    rng.shuffle(X)
    return X, {"negatives": len(neg), "positives": len(pos),
               "families": ["benign_domains", "english_words",
                            "random_char", "random_alnum", "dictionary_concat"]}


# ------------------------------------------------------------------ vectoriser
def build_vocab(samples, min_df: int = 20, max_features: int = 6000):
    from collections import Counter
    df = Counter()
    for s, _ in samples:
        for name in featurize(s):
            df[name] += 1
    # always keep the named scalar features
    scalars = [n for n in df if n.startswith("f:")]
    ngrams = [(n, c) for n, c in df.items()
              if n.startswith("ng:") and c >= min_df]
    ngrams.sort(key=lambda t: t[1], reverse=True)
    keep = scalars + [n for n, _ in ngrams[:max_features]]
    return {name: i for i, name in enumerate(sorted(keep))}


def vectorize(samples, vocab):
    X = np.zeros((len(samples), len(vocab)), dtype=np.float32)
    y = np.zeros(len(samples), dtype=np.float32)
    for r, (s, label) in enumerate(samples):
        for name, val in featurize(s).items():
            j = vocab.get(name)
            if j is not None:
                X[r, j] = val
        y[r] = label
    return X, y


# --------------------------------------------------------------------- training
def train_lr(X, y, epochs=300, lr=0.5, l2=1e-4, batch=512, seed=SEED):
    rng = np.random.default_rng(seed)
    n, d = X.shape
    w = np.zeros(d, dtype=np.float64)
    b = 0.0
    idx = np.arange(n)
    for _ in range(epochs):
        rng.shuffle(idx)
        for start in range(0, n, batch):
            bi = idx[start:start + batch]
            xb, yb = X[bi], y[bi]
            z = xb @ w + b
            p = 1.0 / (1.0 + np.exp(-np.clip(z, -60, 60)))
            g = p - yb
            gw = xb.T @ g / len(bi) + l2 * w
            gb = g.mean()
            w -= lr * gw
            b -= lr * gb
    return w, b


def evaluate(X, y, w, b, thr=0.5):
    p = 1.0 / (1.0 + np.exp(-np.clip(X @ w + b, -60, 60)))
    pred = (p >= thr).astype(np.float32)
    tp = float(((pred == 1) & (y == 1)).sum())
    tn = float(((pred == 0) & (y == 0)).sum())
    fp = float(((pred == 1) & (y == 0)).sum())
    fn = float(((pred == 0) & (y == 1)).sum())
    acc = (tp + tn) / len(y)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"accuracy": round(acc, 4), "precision": round(prec, 4),
            "recall": round(rec, 4)}


def main():
    from datetime import datetime, timezone
    samples, prov = build_dataset()

    # hold out 15% for an honest self-check (real-domain generalisation is in tests)
    rng = random.Random(SEED)
    rng.shuffle(samples)
    cut = int(len(samples) * 0.85)
    train, val = samples[:cut], samples[cut:]

    vocab = build_vocab(train)
    Xtr, ytr = vectorize(train, vocab)
    Xva, yva = vectorize(val, vocab)
    w, b = train_lr(Xtr, ytr)
    metrics = {"train": evaluate(Xtr, ytr, w, b),
               "val": evaluate(Xva, yva, w, b)}

    out = {
        "model": "logistic_regression",
        "features": "char_ngrams(2,3)+boundary+linguistic_scalars",
        "vocab": vocab,
        "weights": [round(float(x), 6) for x in w],
        "bias": round(float(b), 6),
        "threshold": 0.5,
        "meta": {
            "trained_utc": datetime.now(timezone.utc).isoformat(),
            "seed": SEED,
            "n_train": len(train), "n_val": len(val),
            "n_features": len(vocab),
            "data_provenance": prov,
            "metrics": metrics,
            "note": ("Positives are faithful reproductions of published DGA "
                     "family structures (random + dictionary-concat), not any "
                     "single botnet seed. Replace with labeled feeds and re-run "
                     "to harden. Generalisation to real DGAs is asserted in "
                     "tests/test_dga_classifier.py against published IOCs."),
        },
    }
    os.makedirs(MODELS, exist_ok=True)
    dest = os.path.join(MODELS, "dga_lr.json")
    json.dump(out, open(dest, "w"), indent=1)
    print(f"[*] wrote {dest}")
    print(f"    features={len(vocab)}  train={metrics['train']}  val={metrics['val']}")


if __name__ == "__main__":
    main()
