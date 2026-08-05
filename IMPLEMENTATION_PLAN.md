# E-Rakshak — Windows C2/Exfiltration Module: Implementation Plan

**Purpose of this document.** A complete, dependency-ordered build plan to take
the module from a well-architected prototype to an expert-credible, court-usable
forensic malware-analysis tool for law-enforcement and government use. No time
boxes — this is the full scope and the order to build it in.

---

## 1. North Star

Given a malware sample (and, when available, its sandbox detonation artifacts),
the module produces an **attributed, evidence-graded, court-admissible account**
of:

1. **What the malware does** — capabilities, family, host actions (static +
   dynamic).
2. **What it steals** — the specific data items collected (credentials, cookies,
   keystrokes, OTPs, wallets, files), identified individually.
3. **Where it sends them** — every exfiltration/C2 destination, the protocol, and
   **which stolen item went where** (item-level provenance).

Operating context: **air-gapped, offline, single-sample forensic analysis.** A
human analyst reviews every case, so the design bias is **recall-first with
ranked, explainable candidates** — never silently drop a signal, always show why.

---

## 2. Design principles (non-negotiable)

1. **Explainable, deterministic core.** Every verdict must be reconstructable and
   defensible in court. Heuristics + signatures + correlation form the core. ML is
   used only where it is the standard, interpretable tool (see §7).
2. **Stand on Zeek.** Zeek is the authoritative parser (industry-grade protocol
   coverage). We build detection/correlation/evidence on top of Zeek logs. Scapy
   is the offline fallback only.
3. **Evidence integrity & chain of custody.** Inputs hashed, runs deterministic
   and reproducible, findings hash-chained, case metadata preserved.
4. **Recall-first, ranked candidates.** Surface everything; grade confidence
   (confirmed / strong / weak); let the analyst triage. Missing a crime is worse
   than a low-confidence candidate.
5. **Offline-first.** Every capability must work air-gapped; connected feeds are
   an optional refresh, never a runtime dependency.
6. **Shared cross-platform schema.** Output parity with the Android module;
   ATT&CK-mapped throughout.

---

## 3. Current baseline (what exists today)

- Network detection: beaconing, HTTP volume exfil, FTP-STOR exfil, private-IP
  filtering (IPv4+IPv6, 6to4).
- Attribution: GeoIP/ASN (GeoLite2), local threat-intel reputation, JA3
  (auto-extracted) + FTPS mitigation.
- Correlation: host↔network via ETW **interface built, fixture-fed**.
- Confidence tiering (confirmed/strong/weak); tiered validation harness.
- Evidence: hash-chained `exfil_events` schema; CSV + STIX 2.1 export; Postgres.
- Tooling: NetMon→pcap converter, synthetic FTP traffic generator.
- 88 tests; validated on 5 malware families, 8 benign controls, an enterprise
  slice, and the Zeek FTP corpus.

This plan **extends** this baseline; it does not discard it.

---

## 4. Target architecture

```
                          ┌───────────────────────── SAMPLE INTAKE ─────────────────────────┐
   malware sample ───────►│ hash / file-type / packer ID · case metadata · chain of custody  │
                          └───────┬──────────────────────────────────────────┬──────────────┘
                                  │                                           │
                    ┌─────────────▼─────────────┐               ┌─────────────▼──────────────┐
                    │  STATIC ANALYSIS (B)       │               │  DYNAMIC (sandbox team)     │
                    │  YARA · CAPA capabilities  │               │  detonation → PCAP + ETW    │
                    │  family config/IOC extract │               │  host access events         │
                    └─────────────┬─────────────┘               └───────┬─────────────┬───────┘
                                  │ static IOCs / expected C2            │ PCAP        │ ETW
                                  │                                      ▼             ▼
                                  │                        ┌──────────────────┐  ┌──────────────┐
                                  │                        │ ZEEK-PRIMARY      │  │ etw_ingest   │
                                  │                        │ ingestion (A)     │  │ (host)       │
                                  │                        │ conn/dns/ssl/http │  └──────┬───────┘
                                  │                        │ /files/x509 logs  │         │
                                  │                        └────────┬──────────┘         │
                                  │                                 ▼                    │
                                  │             ┌───────────── NETWORK DETECTION (C) ─────┴──┐
                                  │             │ DNS-tunnel/DoH/DGA · TLS(JA4/cert) · HTTP  │
                                  │             │ cloud/SaaS · SMTP/FTP · covert · beacon    │
                                  │             └────────────────────┬───────────────────────┘
                                  │                                  ▼
                                  └──────────────► ATTRIBUTION + TI (F) ─► CORRELATION v2 (E)
                                                                            + EXFIL CONTENT &
                                                                            ITEM PROVENANCE (D)
                                                                                   │
                                                                                   ▼
                                                                    REPORTING / IOC / STIX (G)
                                                                    evidence chain · timeline
```

---

## 5. Workstreams

Each workstream lists its components, key deliverables, acceptance criteria, and
dependencies. Build order is in §9.

### A. Zeek-primary ingestion & unified data model
- **A1 Zeek log ingestion.** Parse `conn.log`, `dns.log`, `ssl.log`, `http.log`,
  `files.log`, `x509.log`, `smtp.log`, `ftp.log`, `weird.log`. Normalize into an
  internal session/flow/transaction model. Scapy path becomes the fallback.
- **A2 Unified data model.** Extend `Connection` into a richer model: `Session`
  (transport), `Transaction` (protocol-level: DNS query, HTTP request, FTP/SMTP
  command), and `Artifact` (a file/blob transferred). Every object carries
  timestamps + provenance back to the raw evidence.
- **A3 Evidence & chain of custody.** Hash all inputs (sample, pcap, logs);
  record tool versions, rule versions, run parameters; make runs deterministic;
  extend the hash chain to cover the whole case, not just exfil rows.
- **Acceptance:** the existing 5 malware pcaps produce identical findings via the
  Zeek path as via scapy; case manifest reproducible bit-for-bit.
- **Depends on:** Zeek installed on the analyst box (fallback covers absence).

### B. Static analysis — SCOPED TO INTERFACE + CORRELATION (not a redundant engine)
> **Decision:** the static-analysis *engine* (unpacking, YARA, CAPA, config
> extraction) lives in the ST/DT module; duplicating it here would be redundant.
> This module owns only what is unique to attribution/correlation: **ingesting
> ST/DT's static IOC prior and cross-validating it against observed network
> traffic.** ✅ DONE — `static_prior.py`, `docs/static_prior_contract.md`: a
> matched static C2 promotes the network finding to *confirmed*; unobserved
> static IOCs are recorded as dormant. Full extraction stays open on the ST/DT
> side of the contract. The items below (B1–B5) are ST/DT responsibilities,
> consumed here via the prior.

### B (original, ST/DT-owned). Static analysis subsystem ("what it does", from the binary)
- **B1 Intake/triage.** SHA-256, file-type (PE/ELF/APK/script), packer/entropy
  detection, embedded-resource enumeration.
- **B2 YARA engine.** Curated + community rules for family/capability tagging.
- **B3 Capability analysis.** Integrate **CAPA** → ATT&CK-mapped capabilities
  (keylogging, credential access, screen capture, persistence, anti-analysis).
- **B4 Family config/IOC extraction.** Per-family extractors that pull embedded
  C2/exfil destinations, keys, and credentials directly from the binary — for
  the families we already have samples of (RedLine, AgentTesla, Lumma, Snake) and
  extensible thereafter. **This yields ground-truth "where it sends" without
  detonation** and is a forensic force-multiplier.
- **B5 String/artifact mining.** URLs, IPs, domains, email addrs, credential and
  wallet patterns, Telegram/Discord tokens.
- **Acceptance:** for each in-hand family, static extraction recovers the C2/exfil
  destination that the network stage independently confirms.
- **Depends on:** YARA, CAPA (both offline-capable).

### C. Network detection engine (broaden coverage — "where it sends")
- **C1 DNS analysis.** Tunneling + DoH exfil (subdomain entropy, query volume,
  TXT/NULL/CNAME abuse, encoding detection) and **DGA** detection. ML-assisted
  where appropriate (§7).
- **C2 TLS/HTTPS analysis.** **JA4/JA4S/JA4X** fingerprints (add alongside JA3),
  certificate analysis (self-signed, short-lived, suspicious issuers, CN/SNI
  mismatch), SNI reputation, encrypted-beacon timing.
- **C3 HTTP exfil depth.** Stealer gate patterns, multipart/form-grab parsing,
  base64/encoded payload detection, user-agent anomalies.
- **C4 Cloud/SaaS exfil.** Service-aware detection for **Telegram bot API,
  Discord webhooks, pastebin, Mega, Google Drive, Dropbox** — where "public IP"
  reputation fails because the host is legitimate. Detect the abuse pattern, not
  the IP.
- **C5 SMTP + FTP exfil.** Add **SMTP** (AgentTesla's classic channel — creds and
  attachments in cleartext/STARTTLS); extend existing FTP.
- **C6 Covert channels.** ICMP tunneling, protocol-on-nonstandard-port,
  protocol/port mismatch.
- **C7 Beaconing v2.** Long-and-slow intervals, jitter models, multi-modal timing
  (builds on the near-zero-interval fix already landed).
- **Acceptance:** each detection class has ≥1 real positive sample and ≥1 benign
  control; per-class recall reported in the benchmark (§8).
- **Depends on:** A (Zeek logs feed most of these directly).

### D. Exfil content reconstruction & item-level provenance (the OTP requirement)
- **D1 Payload reconstruction.** ✅ `content_recon.py` — reassembles outbound
  cleartext streams (HTTP/FTP/SMTP), recovers the actual exfiltrated content,
  SHA-256-hashes it for evidence, previews it, and attaches it to the provenance
  record. Zeek `files.log` used when present. Validated on real AgentTesla/SMTP.
- **D2 Stolen-data classification.** Classify each recovered item: credential,
  **OTP/2FA code**, cookie/session, browser autofill, crypto wallet, keystroke
  log, document, system info. Pattern + structure based, explainable.
- **D3 Item→destination provenance graph.** Link each identified item to the
  host API that accessed it (from ETW) and to the exact network flow/destination
  that carried it — producing statements like *"OTP captured via GetClipboardData
  at 14:03:01 was exfiltrated to 198.51.100.7 over HTTPS at 14:03:04."*
- **D4 Encrypted-exfil inference.** When payload is opaque, infer likely stolen
  content from host access events immediately preceding the upload (credential
  read → likely credential exfil), clearly labelled as inference, not capture.
- **Acceptance:** on a cleartext-exfil sample, produce a correct item→destination
  provenance chain; on an encrypted one, produce a correctly-tiered inference.
- **Depends on:** A2 (artifact model), E (ETW correlation), C.

### E. Host↔network correlation v2
- **E1 Real ETW integration.** Finalize with the sandbox team using the built
  `etw_ingest` contract + clock-sync guard; move off the fixture.
- **E2 Correlation hardening.** Many-to-many → best-match-per-access; causal
  chains (access → staging → exfil); feed the provenance graph (D3).
- **E3 Unified timeline.** ✅ `timeline.py` — single host+network kill-chain
  timeline per case, time-ordered, ATT&CK-annotated with kill-chain phase.
- **Acceptance:** correlation runs on real ETW output; timeline reconstructs the
  documented behaviour of an in-hand sample.
- **Depends on:** sandbox team ETW emission (external); interface already built.

### F. Threat intelligence & attribution
- **F1 Feed integration at scale.** ✅ `feed_import.py` (Feodo, URLhaus, JA3, JA4,
  generic domain/DGA lists) + offline `refresh <dir>` + `stats`; **domain
  reputation** (`attribution.domain_reputation`) wired so a known-bad domain
  promotes DNS/cloud/HTTP findings to *confirmed*. MISP pull remains the connected
  upgrade path (same table).
- **F2 Known-good baseline / allowlist.** ✅ `allowlist.py` + `data/allowlist.json`
  — narrow sanctioned-service list; down-tiers WEAK findings to `allowlisted`
  (annotated, never hidden); confirmed/strong untouched (confirmed wins vs
  domain-fronting); exfil-abused services (Drive/Telegram/Discord) pointedly
  excluded.
- **F3 Family/campaign attribution.** ✅ `family_attribution.py` — fuses static-
  prior family (confirmed), threat-intel notes / known-bad fingerprints (likely),
  and behavioural signatures (possible) into ranked, explainable verdicts. Emits
  `output/attribution.json`. **Workstream F complete.**
- **Acceptance:** confirmed-tier recall rises as feed coverage improves; allowlist
  demonstrably drops benign cloud flags a tier without hiding them.

### G. Reporting & output (court-ready)
- **G1 Forensic report generator.** Structured report: executive summary,
  per-finding evidence with explanation, item→destination provenance, unified
  timeline, ATT&CK matrix, IOC appendix, chain of custody, reproducibility hash.
  PDF + HTML.
- **G2 IOC/STIX export.** Extend current CSV + STIX 2.1 with the new artifact and
  provenance data.
- **G3 Analyst triage view.** Ranked candidates with drill-down (report-embedded
  initially; standalone UI later).
- **G4 Verification mode.** Re-run a case and verify the hash chain + determinism.
- **Acceptance:** a generated report is self-contained, explainable to a
  non-specialist, and independently verifiable.

### H. Testing, benchmarking & hardening (continuous)
- **H1 Corpus expansion.** Multi-family, multi-technique real samples; benign
  controls per technique; standard datasets (CTU-13, CIC-IDS, DNS-tunnel sets).
- **H2 Benchmark harness.** Per-technique recall + tiered precision/recall +
  false-positive rate; published, reproducible numbers.
- **H3 Adversarial/evasion testing.** Obfuscated/encoded/encrypted/tunnelled
  exfil; the synthetic traffic generator extended per technique.
- **H4 Robustness & performance.** Malformed-input fuzzing; profiling on
  detonation-scale captures via Zeek.
- **H5 Regression CI.** Every workstream ships with tests; nothing regresses the
  85+ existing.
- **Acceptance:** a coverage matrix (§6) with a measured recall per row.

---

## 6. Detection coverage matrix (target)

Each row = a technique the tool must handle, with its detection method and
ATT&CK id. This matrix is the definition of "great coverage" and the benchmark's
backbone.

| Technique | ATT&CK | Detection method | Status |
|---|---|---|---|
| HTTP(S) C2 / gate | T1071.001 | pattern + JA4 + timing + rep | ✅ have |
| Exfil over C2 | T1041 | volume/ratio + content | have |
| FTP exfil (STOR) | T1048 | control-channel command | have |
| SMTP exfil | T1048.003 | smtp.log + attachment/creds | ✅ have |
| Cloud/SaaS exfil (Telegram/Discord/Mega/Drive) | T1567 | service-aware, risk-tiered | ✅ have |
| DNS tunneling | T1071.004 | entropy/volume/records | ✅ have |
| DNS-over-HTTPS exfil | T1572 | DoH endpoint + timing | ✅ have (endpoint) |
| DGA C2 | T1568.002 | entropy/NXDOMAIN | ✅ have |
| Encrypted C2 (TLS) | T1573 | JA3+JA4/cert/SNI/timing | ✅ have |
| ICMP / covert channel | T1095 | protocol anomaly | ✅ have |
| Non-standard port C2 | T1571 | protocol/port mismatch | ✅ have |
| Beaconing | T1071 | jitter/interval + size regularity | ✅ have (v2) |
| Credential access (host) | T1555/T1056 | ETW correlation | interface |
| Data staged before exfil | T1074 | correlation/timeline | **new** |

---

## 7. ML usage policy (deliberate and bounded)

ML is applied **only** where it is the standard, interpretable tool and where
offline pretrained models or standard datasets exist. It never replaces the
explainable core, and every ML verdict is accompanied by the human-readable
features that drove it.

- **Yes:** DGA domain classification; DNS-tunneling statistical classification;
  malware-family classification from static features (e.g. EMBER-style);
  encrypted-traffic/JA4 clustering.
- **No:** network-wide behavioural-baseline anomaly detection — the single-sample
  clean-sandbox model has no "normal" to baseline against, and black-box scoring
  is a liability for court admissibility.
- **No:** a "new/previously-unseen destination" filter. This is a specific case of
  the baseline non-goal above: it presupposes persistent cross-run state (a set of
  destinations seen before) to diff against, which the clean-sandbox, per-case,
  deterministic-`case_id` model does not keep and must not depend on. In a pristine
  detonation every external destination is the sample's doing, so a novelty filter
  would either flag everything or risk *hiding* a real C2 that also carries benign
  traffic — the opposite of a recall-first forensic posture. The legitimate intent
  (don't drown the analyst in already-explained egress) is served instead, without
  any baseline, by the catch-all's `covered_dsts` residual filter — it surfaces only
  egress *not* already explained by a specific detector — and by the F2 sanctioned-
  service allowlist, which down-tiers known-good update/telemetry/OCSP noise without
  ever hiding it.
- **Constraint:** any ML component ships with its training data provenance, is
  reproducible offline, and outputs feature-level explanations.

---

## 8. Testing & benchmarking strategy

- **Recall-first metric.** Primary metric is per-technique recall (did we surface
  the malicious activity), reported alongside tiered precision.
- **Coverage matrix as scoreboard** (§6): every row gets ≥1 positive sample and a
  measured recall.
- **Benign controls per technique** to keep precision honest (the negative-control
  harness already exists; extend it).
- **Standard datasets** for external credibility (CTU-13, CIC-IDS, DNS-tunnel).
- **Adversarial suite** via the synthetic generator (obfuscated/encoded/tunnelled).
- **Reproducibility test:** identical inputs → identical case manifest + hash.
- **Regression CI** gating every change.

---

## 9. Build sequencing (dependency-ordered)

Not time-boxed; ordered so each phase unlocks the next.

**Phase 1 — Foundation. ✅ DONE**
A1 Zeek-primary ingestion (`zeek_ingest.py`, TSV+JSON) → A2 unified data model
(`model.py`: Session/Transaction/Artifact + `to_connections` bridge) → A3
evidence/chain-of-custody (`evidence.py`: hashed inputs, deterministic case_id,
`verify_chain`). Orchestrator is Zeek-primary with scapy fallback; 107 tests
pass; detection results identical across both ingestion paths.

**Phase 2 — Coverage breadth (network). ✅ DONE**
C1 DNS(tunnel/DoH/DGA) → C4 cloud/SaaS → C5 SMTP → C2 TLS/JA4+cert → C3 HTTP depth
→ C6 covert (ICMP/port) → C7 beacon v2. All ATT&CK-mapped, tiered, and tested;
the coverage matrix rows above are now ✅. Modules: `dns_analysis`, `app_exfil`,
`tls_analysis`, `http_analysis`, `covert_channels`. *Rationale delivered: closed
the "where it sends" gaps that matter most for LE; each rides on Phase 1's Zeek
logs.*

**Phase 3 — Static subsystem.**
B1 intake → B2 YARA → B3 CAPA → B4 config extraction → B5 string mining.
*Rationale: independent of the sandbox team; delivers ground-truth "what it does /
where it sends" and cross-checks the network stage.*

**Phase 4 — Provenance & correlation. ✅ DONE (E1 external)**
D1 content reconstruction (`content_recon.py` — recovers the actual outbound
bytes, SHA-256-hashed, previewed; attached to provenance), D2 classification,
D3 item→destination provenance (`provenance.py`), D4 encrypted-exfil inference,
E2 correlation hardening (best-match, clock-sync guarded), E3 unified ATT&CK-
annotated kill-chain timeline (`timeline.py`). Validated on real samples — e.g.
AgentTesla FTP: *"system_info via GetComputerNameExW → 93.89.225.40 over FTP —
recovered 883 B (sha256 d94161992ceb…)"*. **ETW hardening method:** real ETW is
the sandbox team's (E1, external), so correlation is hardened/tested with a
synthetic scenario generator (`tools/etw_scenario_gen.py`). *Remaining:* **E1
real ETW only** (external dependency; interface built and fixture-ready).

**Phase 5 — Intel, reporting, hardening.**
F feeds/allowlist/attribution → G forensic report/STIX/verification → H full
benchmark + adversarial + standard-dataset evaluation. *Rationale: turns findings
into court-ready, measured, defensible output.*

Testing (H) runs continuously across all phases, not only at the end.

---

## 10. Dependencies, risks, open decisions

**External dependencies:** Zeek (analyst box); YARA + CAPA rule sets; ETW
emission from the sandbox/ST-DT team (interface already built); GeoLite2; offline
TI feed bundles.

**Risks:**
- ETW real-data slip (external) — mitigated: network + static stages fully
  functional without it; correlation degrades gracefully to fixture/inference.
- Family config extractors are per-family effort — prioritize in-hand families,
  make the framework pluggable.
- Encrypted exfil fundamentally limits content recovery — handled via labelled
  inference (D4), never overstated.
- Standard-dataset scale (CIC-IDS full) — handled by Zeek-primary + slicing.

**Decisions (resolved):**
1. **Report format:** keep simple (whatever is easiest) for now; revisit later.
2. **Static extractors:** target all families; research to set a priority order
   among them where effort must be spent.
3. **Analyst UI:** out of scope now — harden functionality first, UI later.
4. **Packaging:** container-based deployment for the air-gapped analyst box.
