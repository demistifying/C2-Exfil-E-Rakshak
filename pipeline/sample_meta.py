"""
sample_meta.py — ingest the ST/DT bundle's `sample.meta.json`.

================================ WHY THIS EXISTS =============================
Every WinST/DT handoff bundle ships `sample.meta.json` (schema:
schemas/sample_meta.schema.json on their side). Until now this module consumed
none of it, which left the single strongest *independent* corroboration source
in the bundle unused.

It matters because of how our confidence tiering is defined:

    confirmed = independent threat-intel hit AND behavioural correlation
    strong    = strong behavioural lineage, no independent hit

A YARA deep hit, a ClamAV signature, or a VirusTotal detection ratio is exactly
such an independent signal — it is derived from the BINARY, not from the traffic
we are scoring. So a destination that we correlated behaviourally AND whose
sample is independently flagged static-side is legitimately `confirmed`, where
behaviour alone would cap at `strong`.

------------------------------ SCOPE BOUNDARY ---------------------------------
`sample.meta.json` carries NO network indicators. Its fields are hashes,
file_type, static_risk_score, static_hypotheses[], yara{fast,deep}, clamav, and
vt_lookup. There are no domains, IPs, URLs or decrypted C2 configs in it.

The ST/DT implementation plan describes family config decryptors (AsyncRAT /
njRAT / QuasarRAT) that pull hardcoded C2 out of the binary before execution,
but **the handoff contract currently has no field carrying those to us**. That
is a genuine gap in the contract, not something this module can work around.
Until ST/DT emits them (either a `c2_static_prior.json` artifact or an
`iocs[]` array on sample.meta), `static_prior.py` has no bundle-native source
and must be fed a prior file explicitly.

This module therefore contributes: sample identity, family hints, capability
hints, and independent corroboration — but not IOCs.
==============================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field
import json
import os
import re

# YARA rule / ClamAV signature name -> canonical family. Deliberately small and
# conservative: a wrong family label in a police report is worse than none.
_FAMILY_PATTERNS = [
    (re.compile(r"redline", re.I), "RedLine Stealer"),
    (re.compile(r"asyncrat", re.I), "AsyncRAT"),
    (re.compile(r"njrat|bladabindi", re.I), "njRAT"),
    (re.compile(r"quasar", re.I), "QuasarRAT"),
    (re.compile(r"lumma", re.I), "Lumma Stealer"),
    (re.compile(r"stealc", re.I), "StealC"),
    (re.compile(r"agent[_\-]?tesla", re.I), "AgentTesla"),
    (re.compile(r"snake[_\-]?key", re.I), "Snake KeyLogger"),
    (re.compile(r"formbook|xloader", re.I), "FormBook"),
    (re.compile(r"remcos", re.I), "Remcos"),
]

# static_hypotheses strings -> ATT&CK technique ids, for the capability layer.
_HYPOTHESIS_TECHNIQUES = {
    "packed": "T1027.002",
    "obfuscated": "T1027",
    "suspicious_imports:CreateRemoteThread": "T1055",
    "suspicious_imports:SetWindowsHookEx": "T1056.001",
    "suspicious_imports:CryptUnprotectData": "T1555.003",
    "suspicious_imports:BitBlt": "T1113",
    "dotnet": None,
}


@dataclass
class SampleMeta:
    sample_sha256: str | None = None
    sample_md5: str | None = None
    sample_sha1: str | None = None
    file_type: str | None = None
    static_risk_score: float | None = None
    static_hypotheses: list[str] = field(default_factory=list)
    yara_fast_hits: list[str] = field(default_factory=list)
    yara_deep_hits: list[str] = field(default_factory=list)
    clamav_status: str | None = None
    clamav_signature: str | None = None
    vt_lookup: str | None = None
    errors: list[str] = field(default_factory=list)
    path: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def yara_hits(self) -> list[str]:
        return list(self.yara_fast_hits) + list(self.yara_deep_hits)

    @property
    def clamav_detected(self) -> bool:
        return (self.clamav_status or "").lower() in {"infected", "found", "detected"}

    @property
    def vt_detected(self) -> bool:
        """True when vt_lookup reports at least one malicious detection.

        vt_lookup is a free-form string on the ST/DT side ("not_configured",
        "unavailable", or a ratio like "54/72"). Anything we cannot positively
        read as a detection is treated as NOT a hit — never invent corroboration.
        """
        s = (self.vt_lookup or "").strip().lower()
        if not s or s in {"not_configured", "unavailable", "clean", "not_found"}:
            return False
        m = re.match(r"^(\d+)\s*/\s*(\d+)$", s)
        if m:
            return int(m.group(1)) > 0
        return False

    @property
    def family(self) -> str | None:
        """Best-effort family from YARA rule names, then the ClamAV signature."""
        for name in self.yara_deep_hits + self.yara_fast_hits + [self.clamav_signature or ""]:
            for pat, fam in _FAMILY_PATTERNS:
                if pat.search(name or ""):
                    return fam
        return None

    def corroborating_signals(self) -> list[str]:
        """Independent, binary-derived signals usable to PROMOTE confidence.

        Deliberately excludes static_risk_score and static_hypotheses: those are
        heuristics computed from the same binary inspection, not independent
        detections, and treating them as corroboration would inflate tiers.
        """
        sig: list[str] = []
        if self.yara_deep_hits:
            sig.append(f"yara_deep:{','.join(self.yara_deep_hits[:3])}")
        elif self.yara_fast_hits:
            sig.append(f"yara_fast:{','.join(self.yara_fast_hits[:3])}")
        if self.clamav_detected:
            sig.append(f"clamav:{self.clamav_signature or 'detected'}")
        if self.vt_detected:
            sig.append(f"virustotal:{self.vt_lookup}")
        return sig

    @property
    def independently_flagged(self) -> bool:
        return bool(self.corroborating_signals())

    def capability_techniques(self) -> list[str]:
        out = []
        for h in self.static_hypotheses:
            t = _HYPOTHESIS_TECHNIQUES.get(h)
            if t and t not in out:
                out.append(t)
        return out


def ingest_sample_meta(raw: dict, *, strict: bool = False) -> SampleMeta:
    meta = SampleMeta()
    if not isinstance(raw, dict):
        msg = "sample.meta.json must be a JSON object"
        if strict:
            raise ValueError(msg)
        meta.errors.append(msg)
        return meta

    sv = raw.get("schema_version")
    if sv is not None and sv != "1.0":
        msg = f"sample_meta schema_version {sv!r} != supported '1.0'"
        if strict:
            raise ValueError(msg)
        meta.errors.append(msg)

    meta.sample_sha256 = raw.get("sample_sha256")
    meta.sample_md5 = raw.get("sample_md5")
    meta.sample_sha1 = raw.get("sample_sha1")
    meta.file_type = raw.get("file_type")

    try:
        if raw.get("static_risk_score") is not None:
            meta.static_risk_score = float(raw["static_risk_score"])
    except (TypeError, ValueError):
        meta.errors.append("static_risk_score is not numeric")

    hyp = raw.get("static_hypotheses")
    if isinstance(hyp, list):
        meta.static_hypotheses = [str(h) for h in hyp]
    elif hyp is not None:
        meta.errors.append("static_hypotheses must be an array")

    yara = raw.get("yara")
    if isinstance(yara, dict):
        meta.yara_fast_hits = [str(x) for x in (yara.get("fast_hits") or [])]
        meta.yara_deep_hits = [str(x) for x in (yara.get("deep_hits") or [])]
    elif yara is not None:
        meta.errors.append("yara must be an object with fast_hits/deep_hits")

    clam = raw.get("clamav")
    if isinstance(clam, dict):
        meta.clamav_status = clam.get("status")
        meta.clamav_signature = clam.get("signature")
    elif clam is not None:
        meta.errors.append("clamav must be an object with status/signature")

    vt = raw.get("vt_lookup")
    meta.vt_lookup = None if vt is None else str(vt)
    return meta


def load_sample_meta(path: str, *, strict: bool = False) -> SampleMeta:
    """Load sample.meta.json. A missing file is an error on the report, not an
    exception — a bundle without it is degraded, not unusable."""
    if not path or not os.path.exists(path):
        return SampleMeta(errors=[f"file not found: {path}"], path=path)
    try:
        raw = json.load(open(path, encoding="utf-8"))
    except json.JSONDecodeError as e:
        return SampleMeta(errors=[f"invalid JSON: {e}"], path=path)
    meta = ingest_sample_meta(raw, strict=strict)
    meta.path = path
    return meta


def load_from_handoff(h, *, strict: bool = False) -> SampleMeta:
    """Convenience: resolve sample.meta.json from a loaded Handoff bundle."""
    return load_sample_meta(getattr(h, "sample_meta_path", None), strict=strict)


# --- promotion --------------------------------------------------------------

_RANK = {"allowlisted": 0, "unconfirmed": 1, "weak": 2, "strong": 3, "confirmed": 4}


def promote_with_static_corroboration(events: list, meta: SampleMeta | None) -> list[str]:
    """Promote `strong` findings to `confirmed` when the SAMPLE is independently
    flagged static-side.

    Rules, kept deliberately tight:
      * Only `strong` is promoted. A `weak` finding is weak because the
        behavioural evidence itself is thin; an unrelated static hit does not
        fix that, and promoting it would be exactly the "beacon alone becomes a
        verdict" failure this module exists to avoid.
      * Findings already `confirmed` are untouched.
      * Anything capped by a caveat (bad clock, degraded telemetry, simulated
        network) is NOT promoted — a cap is a statement that the evidence is
        unreliable, and static corroboration does not repair it.

    Mutates events in place. Returns human-readable notes.
    """
    if not meta or not meta.independently_flagged or not events:
        return []
    signals = meta.corroborating_signals()
    promoted = 0
    for e in events:
        get = (lambda k: e.get(k)) if isinstance(e, dict) else (lambda k: getattr(e, k, None))
        setr = (e.__setitem__ if isinstance(e, dict)
                else lambda k, v: setattr(e, k, v))
        if get("capped_by_caveat"):
            continue
        if get("confidence_tier") != "strong":
            continue
        setr("confidence_tier", "confirmed")
        setr("static_corroboration", signals)
        promoted += 1
    if not promoted:
        return []
    return [(f"STATIC CORROBORATION ({'; '.join(signals)}): {promoted} finding(s) "
             f"promoted strong -> confirmed. The sample is independently flagged "
             f"by binary-side analysis, which is evidence separate from the "
             f"observed traffic.")]
