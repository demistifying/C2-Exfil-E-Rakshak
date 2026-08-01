# Windows C2/Exfiltration Module — Project Status

**Module role:** the network-side detection spine of the Unified Cross-Platform
Malware Analysis Suite (ERH26_PS_04). It ingests a PCAP of malware traffic and,
in collaboration with the Windows ST/DT sandbox module, produces attributed,
evidence-graded C2/exfiltration findings in a schema shared with the Android
module.

**Snapshot (Phases 1–4 core complete):** **191 tests passing.** Adds host↔network
correlation hardening (best-match, clock-sync guarded) and **item-level exfil
provenance** — "which stolen item left via what channel to which destination,
when" — tested across every item type, every exfil protocol, negatives, window
boundaries, and a full multi-item multi-channel stealer scenario. Real ETW is
hardened via a synthetic scenario generator (`tools/etw_scenario_gen.py`) until
the sandbox team wires live events. Also: static-IOC-prior interface + static↔
network correlation (a binary-extracted C2 seen on the wire → confirmed). Zeek-primary ingestion
+ a unified data model, and a broad modern-technique detection engine — DNS
tunnelling / DGA / DoH, cloud/SaaS (Telegram/Discord/Drive), SMTP, JA3 + **JA4** +
TLS-certificate, HTTP-gate, ICMP / non-standard-port covert channels, and
beaconing v2 — every detection ATT&CK-mapped, confidence-tiered, and
evidence-chained. See `IMPLEMENTATION_PLAN.md` §6 for the ✅ coverage matrix.

Verdicts are **confidence-tiered** (confirmed / strong / weak): on real
enterprise traffic (CIC-IDS-2017) the raw detectors produced **15 benign false
positives → 0 at the `confirmed` tier**, while all malware C2s stay surfaced at
`any` (recall held). JA3+JA4 are auto-extracted from any pcap (no Zeek), and
**FTPS / AUTH-TLS is mitigated** — an encrypted C2 whose payload is invisible is
still caught by a known-bad fingerprint. Validated on 5 real malware captures
(4 families) + dnscat2 tunnelling, **9 benign controls** (incl. IPv6, FTPS,
malformed-input, downloads, top-1M DNS), the Zeek FTP corpus, an enterprise
slice, and synthetic harnesses. IPv6 / 6to4-tunnelled traffic handled. The one
external dependency (ETW host events) has a built, tested ingestion interface.

---

## 1. Architecture — the pipeline end to end

```
                    ┌──────────────── HOST SIDE (from Windows ST/DT sandbox) ────────────────┐
                    │  ETW access events (JSON)                                              │
                    │        │                                                               │
                    │        ▼                                                               │
                    │  etw_ingest.py  ── validate schema, enum, UTC; map data_type→ATT&CK;   │
                    │        │           assess clock sync vs network timeline               │
                    └────────┼───────────────────────────────────────────────────────────────┘
                             │ validated ETWAccessEvent[]
 PCAP ─► pcap_loader ─► traffic_analysis ─► attribution ──►(JA3 enrich)──►  correlation ─► emit ─► export ─► db_loader
        (Connection[])   beacon + exfil     geo/ASN/rep      ja3_from_pcap /   host↔net     schema   CSV/     Postgres
                         (HTTP vol +         + known-bad JA3   ja3_loader       tiered       (hash    STIX 2.1
                          FTP-STOR)                                             confidence   chain)
```

**Stage by stage:**

1. **Ingestion (network):** `pcap_loader.py` turns a raw PCAP (via scapy) or a
   Zeek `conn.log` into `Connection` records — a subset of Zeek's schema so the
   source is swappable. Sniffs cleartext HTTP and now FTP `STOR`/`STOU`/`APPE`
   commands from client→server payloads.
2. **Ingestion (host):** `etw_ingest.py` is the cross-module front door — it
   validates the sandbox's ETW access events, maps each to an ATT&CK technique,
   and checks clock alignment before correlation.
3. **Detection:** `traffic_analysis.py` — beaconing (jitter-ratio timing) +
   exfil (HTTP upload volume/ratio **and** FTP-STOR, volume-independent), with
   RFC1918/loopback/link-local filtering so internal IPs never flag.
4. **Attribution:** `attribution.py` — offline GeoIP/ASN (GeoLite2) + local
   threat-intel reputation (SQLite, seeded from abuse.ch), including known-bad
   JA3 fingerprints.
5. **Encrypted-traffic path:** `ja3_from_pcap.py` (computes JA3/JA3S from a PCAP,
   no Zeek needed) and `ja3_loader.py` (parses Zeek `ssl.log`) — fingerprints a
   TLS-only C2 with no payload access.
6. **Correlation:** `correlation.py` — links host access (what was stolen) to
   network exfil (where it went) by directional temporal proximity, producing a
   4-tier confidence verdict shared with the Android module.
7. **Emit:** `orchestrator.py` folds everything into the shared `exfil_events`
   schema with a SHA-256 hash chain (tamper-evident, evidence-grade).
8. **Export / load:** `export_iocs.py` (CSV + STIX 2.1), `db_loader.py`
   (PostgreSQL). `validate.py` measures precision/recall vs labeled ground truth.
9. **Feeds:** `feed_import.py` — offline import of abuse.ch feeds (Feodo,
   URLhaus) and known-bad JA3.

---

## 2. What has been done

### Detection & attribution
- **HTTP/beaconing/volume exfil** — original spine, working on real data.
- **FTP-STOR exfil detection (new).** Catches FTP data theft by the explicit
  store command on the control channel, independent of volume. This closed a
  real miss: AgentTesla-style stealers exfil credential dumps under ~2 KB, far
  below any byte threshold. The stolen filename is captured as evidence
  (e.g. `STOR ...Passwords...`).
- **Encrypted-traffic attribution (JA3), validated on real data.** Fingerprinted
  a live TLS C2 (`whitepepper.su`, JA3 `2800f914…`) with no payload access.
- **Known-bad JA3 → reputation.** A known-bad fingerprint (Cobalt Strike, etc.)
  now flags a C2 even when its IP is not itself known-bad.
- **Offline JA3 tooling.** `ja3_from_pcap.py` emits Zeek-format `ssl.log` from a
  PCAP, so the encrypted path runs air-gapped with no Zeek/container runtime.

### Host↔network integration (this phase)
- **`etw_ingest.py` — the ETW ingestion module / integration contract.** Schema
  (`ETWAccessEvent`), strict field/enum/UTC validation, `data_type → ATT&CK`
  mapping, non-strict batch ingest (one bad row is skipped-and-reported, not
  fatal), and a **validator CLI the sandbox team runs** against their own output:
  `python pipeline/etw_ingest.py their_events.json output/network_events.json`.
- **Clock-skew assessment.** Detects host/PCAP clock drift before correlation,
  since skew silently produces false negatives.
- **Correlation now carries ATT&CK technique** into the hash-chained schema, and
  accepts validated events (not raw dicts).
- **Contract doc updated** (`docs/etw_interface_contract.md`) with validator
  usage and a rejection-reason table for the teammate.

### Bugs found and fixed
- **Recall-inflating validation bug.** `validate.py` counted a miss only if the
  malicious IP had already surfaced as a candidate — so a fully-missed C2 didn't
  register, reporting a fake 1.0 recall. Fixed to count any ground-truth IP not
  flagged.
- **Attribution env-var bug.** `attribute()` bound the threat-intel DB path at
  import time, ignoring runtime overrides. Fixed to resolve at call time.
- **Correlation datetime bug.** Validated ETW events store `timestamp` as a
  parsed `datetime`; `correlate()` expected a string and would have crashed on
  real ingested input. Fixed to accept both (caught in review, then verified).

---

## 3. Testing — what is covered

**79 tests, all passing**, by module:

| Test file | Tests | Covers |
|---|---:|---|
| `test_traffic_analysis.py` | 26 | beaconing (regular/irregular/too-few), HTTP exfil, **FTP-STOR** (low-volume, APPE, per-server, negatives), private-IP filtering (**IPv4 + IPv6**) |
| `test_etw_ingest.py` | 17 | schema validation, enum rejection, UTC enforcement, non-strict vs strict, clock-sync (aligned/skewed/before-only), ingestion→correlation handoff |
| `test_correlation.py` | 11 | in-window match, out-of-window miss, negative-delta skip, 4-tier confidence assignment |
| `test_pcap_loader.py` | 10 | scapy + Zeek loading, byte accounting, **native IPv6 + 6to4-tunnel inner-endpoint resolution** |
| `test_attribution.py` | 9 | reputation hit/miss, **known-bad JA3 raise**, graceful degradation (missing DB/GeoLite2) |
| `test_evidence_chain.py` | 6 | hash-chain integrity + tamper detection |

**Live validation:** 5 real malware PCAPs with labeled ground truth —
Redline (HTTP C2), Lumma (TLS C2 / JA3), Snake KeyLogger (FTP, 516 KB),
GuLoader/AgentTesla (FTP, ~1.7 KB), plus a synthetic baseline — and **2 benign
negative controls** (IPv6 FTP, converted from NetMon via `tools/netmon2pcap.py`).
Aggregate **precision 1.0, recall 1.0, F1 1.0**, `tp=5 fp=0 fn=0`, now measured
honestly: both true positives, complete misses (via the FN fix), and false
positives (via the benign controls).

**Testing methodology strengthened:** the FN-accounting fix and the benign
negative-control harness mean the numbers now reflect reality in both
directions — catching bad traffic *and* staying quiet on good traffic.

---

## 4. What is left to do

Ordered by value and by what is in our control.

### A. Precision against benign traffic — ADDRESSED via confidence tiering
Benign-control harness built; precision measured on real enterprise traffic
(CIC-IDS-2017), the Zeek FTP corpus, and a synthetic FTP upload harness. The
CIC slice exposed the real problem — 15 benign cloud endpoints flagged in 11
minutes because behavioural signals were standalone verdicts. Fixed by
**confidence tiering**: `confirmed` (intel/JA3), `strong` (≥2 behaviours),
`weak` (lone signal). Result: **15 benign FPs → 0 at `confirmed`**, recall held
(all 5 C2s surfaced at `any`). Also fixed en route: IPv6/6to4 blind spot, and
near-zero-interval phantom beacons. The synthetic FTP harness
(`tools/ftp_traffic_gen.py`) covers the benign-`STOR`-to-public case real
captures never provided. *Remaining:* thresholds (POST≥1KB, 200KB) still want
tuning, and real-world precision beyond the CIC slice needs more enterprise
traffic.

### B. Detection coverage gaps — in our control, needs samples
- **DNS tunneling / exfil** — the most common evasion path we don't yet detect
  (no DNS analysis at all). Samples: dnscat2/iodine captures.
- **FTPS / encrypted FTP** — both FTP samples were plaintext Pure-FTPd; if the
  malware negotiates explicit TLS, `STOR` is encrypted and our detector is blind.
- **Low-and-slow beaconing** — long-interval C2 to stress jitter thresholds
  (CTU-13 botnet captures).

### C. Correlation hardening — in our control
The logic works but is a first cut, to be hardened: it is temporal co-occurrence
(not proven causation); it is many-to-many (every access×network pair in-window
matches, which can spray low-tier events); and it depends on clock alignment
(now checked). *How:* tune the 15 s window against labeled samples, and collapse
to best-match-per-access.

### D. ETW real-data integration — BLOCKED (external dependency)
Correlation runs on `data/access_events_fixture.json`. It cannot run on real
data until the Windows ST/DT sandbox emits ETW host-access events. *Why not
done:* not our code. *Status:* the ingestion interface, validator, and
clock-skew check are built and tested, so this is a drop-in the moment the
sandbox emits conforming output — and the teammate can self-check with the
validator CLI now.

### E. Operational / minor
- **Docker + Postgres end-to-end** — documented but not run clean top-to-bottom.
- **MITRE refinement** — FTP exfil currently T1041 (Over C2 Channel); T1048
  (Over Alternative Protocol) is more precise.
- **Statistical breadth** — 5 samples is a small n; perfect scores need more
  positives *and* the benign controls (A) to be meaningful.

---

## 5. Dependencies & risks

| Item | Type | Mitigation / status |
|---|---|---|
| ETW host events from sandbox | External blocker | Interface + validator built; fixture-ready |
| Clock sync between host & PCAP | Integration risk | Skew detector added; flagged before correlation |
| Precision on benign traffic | Measurement gap | Harness built; 2 controls pass (0 FP); benign FTP *upload* still untested (4A) |
| IPv6 / tunnelled IPv6 exfil | Coverage (was blind spot) | Fixed — loader reads IPv6 + resolves 6to4/Teredo inner endpoint |
| Encrypted FTP (FTPS) | Detection blind spot | Known; needs FTPS sample + decryption strategy |
| Small validation set | Statistical | Add benign + evasion samples |

---

## 6. Honest positioning (for reviewers)

The individual detectors are **not novel** and we deliberately reuse proven
primitives — Zeek/Suricata parsing, RITA-style jitter beaconing, Salesforce JA3,
abuse.ch feeds. The contribution is the **integration layer** that no
off-the-shelf tool provides for this problem: host↔network correlation tying ETW
host evidence to network exfil, evidence-grade hash-chained output, a shared
cross-platform (Windows/Android) schema, and fully offline/air-gapped operation.
Framing: *"we reuse proven detection, and our work is the correlation,
evidence-integrity, and cross-module-schema layer that turns signals into
attributed, court-usable findings."*
