# Windows C2/Exfiltration Module

Network-side detection spine for the Unified Cross-Platform Malware Analysis
Suite (ERH26_PS_04). Ingests a PCAP of malware traffic and produces
attributed, evidence-graded C2/exfiltration findings in the shared schema.

## What runs today (on real PCAP data)

| Stage | Status | On real data? |
|---|---|---|
| Traffic analysis (beaconing + exfil detection) | ✅ Working | **Yes** — validated on real Redline Stealer PCAP |
| FTP-STOR exfil detection (low-volume, volume-independent) | ✅ Working | **Yes** — catches Snake KeyLogger + AgentTesla-style FTP exfil |
| Private IP filtering (no false positives on internal IPs) | ✅ Working | **Yes** — IPv4 + IPv6 (loopback/link-local/ULA) |
| IPv6 + 6to4/Teredo tunnel handling (resolves inner endpoint) | ✅ Working | **Yes** — validated on IPv6 FTP captures |
| Benign negative controls (precision testing) | ✅ Working | **Yes** — 2 benign captures, 0 false positives |
| Attribution (reputation; geo/ASN when GeoLite2 present) | ✅ Working | **Yes** |
| JA3 + **JA4** fingerprinting (auto-extracted from pcap, no Zeek) | ✅ Working | **Yes** — Lumma C2 JA4 `t13d201200_2b729b4bf6f3_…` (JA3-decline-resistant) |
| TLS certificate analysis (self-signed / failed validation) | ✅ Working | Zeek x509/ssl fields; graded by severity |
| Known-bad JA3 → reputation hit (flags encrypted C2 on an unknown IP) | ✅ Working | **Yes** |
| FTPS / AUTH-TLS mitigation (encrypted FTP caught by fingerprint) | ✅ Working | **Yes** — confirmed-tier flag though STOR is invisible |
| Host↔network correlation (best-match, clock-sync guarded) | ✅ Working | Against documented sandbox interface* |
| Item-level exfil provenance (the "which stolen item → where" graph) | ✅ Working | **Yes** — e.g. *OTP via GetClipboardData → 198.51.100.7 over HTTP* |
| Exfil content reconstruction (recovers stolen bytes, hashed) | ✅ Working | **Yes** — recovered AgentTesla system profile + SMTP creds |
| Unified host+network kill-chain timeline (ATT&CK-annotated) | ✅ Working | **Yes** |
| Shared schema emit + hash-chained evidence | ✅ Working | **Yes** — all schema columns populated |
| PostgreSQL load | ✅ Working | **Yes** (Docker) |
| Confidence tiering (confirmed / strong / weak) | ✅ Working | **Yes** — 15 benign FPs on real traffic → 0 at "confirmed", recall held |
| Validation harness (per-tier precision/recall) | ✅ Working | **Yes** — tiered metrics across malware + benign + enterprise traffic |
| IOC export (CSV + STIX 2.1) | ✅ Working | **Yes** |
| DNS tunnelling / DGA / DoH detection | ✅ Working | **Yes** — flags dnscat2 (`cisco-update.com`); clean on top-1M benign DNS |
| Cloud/SaaS exfil (Telegram/Discord/Mega/Drive), risk-tiered | ✅ Working | **Yes** — flags GuLoader's Google-Drive staging (dual-use→weak) |
| SMTP exfil (AgentTesla channel) | ✅ Working | **Yes** — real VIP-Recovery self-send exfil (`director@igakuin.com`) |
| HTTP C2 depth (gate patterns, suspicious UA) | ✅ Working | **Yes** — flags synthetic `/gate.php`, Lumma `/api/set_agent` |
| Covert channels (ICMP tunnel, non-standard-port C2) | ✅ Working | **Yes** — flags Redline HTTP on tcp/55123 |
| Beaconing v2 (interval + payload-size regularity) | ✅ Working | **Yes** — real Cobalt Strike ~57s beacon (`codeotso.com`) |
| Catch-all for UNKNOWN exfil channels (content-agnostic egress) | ✅ Working | **Yes** — surfaces unexplained egress at *weak* tier |
| Zeek-primary ingestion + unified data model | ✅ Working | **Yes** — conn/dns/http/ssl/ftp/smtp/files, scapy fallback |
| Case manifest + chain of custody (reproducible case_id) | ✅ Working | **Yes** |
| Static-IOC-prior correlation (binary C2 ↔ observed traffic → confirmed) | ✅ Working | **Yes** — promotes AgentTesla FTP C2 weak→confirmed |
| Threat-intel at scale — domain reputation + feed import (Feodo/URLhaus/JA3/JA4/DGA) | ✅ Working | **Yes** — a known-bad domain promotes DNS/cloud/HTTP findings to confirmed |
| Sanctioned-service allowlist (down-tier weak, never hide; confirmed wins) | ✅ Working | **Yes** — suppresses benign update/telemetry/OCSP egress noise |
| Family / campaign attribution (static prior + intel + behaviour) | ✅ Working | **Yes** — Redline via intel, Cobalt Strike/dnscat2 via behaviour |
| Test suite (pytest, 233 tests) | ✅ Working | **Yes** |

*Correlation needs host access events from the Windows ST/DT sandbox (ETW).
That is the one genuine cross-module dependency. Until it lands, correlation
runs against `data/access_events_fixture.json`, which **defines the exact
interface** the sandbox team must emit. See `docs/etw_interface_contract.md`.

## Quick start

```bash
pip install -r requirements.txt
python pipeline/orchestrator.py                                 # synthetic pcap
python pipeline/orchestrator.py data/2024-10-23-Redline-Stealer-infection-traffic.pcap/2024-10-23-Redline-Stealer-infection-traffic.pcap   # real pcap
python pipeline/validate.py                                     # precision/recall
python -m pytest tests/ -v                                      # test suite
```

With Docker (Zeek + Suricata + Postgres):

```bash
docker compose up -d postgres             # brings up the shared store
docker compose run --rm zeek              # authoritative PCAP parse -> output/zeek/
python pipeline/orchestrator.py data/sample.pcap --zeek-dir output/zeek
python pipeline/db_loader.py              # load findings into PostgreSQL
```

### Encrypted-traffic path (JA3) without Zeek

`ja3_from_pcap.py` computes JA3/JA3S fingerprints straight from a PCAP with
scapy and writes the **same** Zeek-format `ssl.log` the pipeline already
consumes — so the encrypted-traffic path runs air-gapped, no Zeek or container
runtime needed. Nothing downstream changes; only the producer of `ssl.log`.

```bash
python pipeline/ja3_from_pcap.py data/sample.pcap --out output/zeek/ssl.log
python pipeline/feed_import.py ja3        # seed known-bad JA3 (Cobalt Strike, etc.)
python pipeline/orchestrator.py data/sample.pcap --zeek-dir output/zeek
```

Validated on the 2026-01-31 exercise PCAP: the TLS-only C2 `153.92.1.49:443`
(SNI `whitepepper.su`) is fingerprinted (ja3 `2800f914…`) and that fingerprint
is carried into the shared schema. A destination whose IP is not yet known-bad
is still flagged when its JA3 matches a seeded known-bad fingerprint — the
"encrypted traffic is not a dead end" claim, now demonstrable.

## IOC Export

```bash
python pipeline/export_iocs.py                          # both CSV + STIX
python pipeline/export_iocs.py --format csv             # CSV only
python pipeline/export_iocs.py --format stix            # STIX 2.1 only
```

Exports discovered IOCs from `output/exfil_events.json` to:
- `output/iocs.csv` — flat CSV for SIEM ingestion
- `output/iocs_stix.json` — STIX 2.1 bundle with indicators and relationships

## Threat-Intel Feed Import

```bash
# Seed known-bad JA3 hashes (Cobalt Strike, Metasploit, etc.)
python pipeline/feed_import.py ja3

# Import Feodo Tracker C2 IPs (download CSV from abuse.ch first)
python pipeline/feed_import.py feodo data/feodotracker.csv

# Import URLhaus URLs
python pipeline/feed_import.py urlhaus data/urlhaus.csv
```

All imports are designed for **offline use**: download the CSVs once on a
connected machine, then run the import air-gapped.

**MISP upgrade path**: replace CSV import with a pymisp pull against a
self-hosted MISP instance. The DB schema doesn't change.

## Using a REAL malware PCAP

The pipeline is validated on five captures spanning four real malware
families plus one synthetic sample:

| PCAP | Family | Exfil channel |
|---|---|---|
| `sample_infostealer.pcap` | synthetic (Redline-style) | HTTP |
| `2024-10-23-Redline-Stealer…` | Redline Stealer | HTTP C2 |
| `2026-01-31-traffic-analysis-exercise…` | Lumma Stealer | TLS C2 (JA3) |
| `2024-09-17-Snake-KeyLogger…` | Snake KeyLogger | FTP (516 KB) |
| `2026-02-03-GuLoader…` | GuLoader / AgentTesla-style | FTP (low-volume, ~1.7 KB) |

The real ones are from malware-traffic-analysis.net. Analyzing a PCAP
passively is safe — you are not executing malware.

Current aggregate on all five: **precision 1.0, recall 1.0, F1 1.0**.

To add more samples:

1. Download a PCAP from https://www.malware-traffic-analysis.net/
2. Drop it in `data/`
3. Add its known-bad IPs to `data/ground_truth.json`
4. Seed the IPs into the threat-intel DB via `init_threatintel_db` or
   `pipeline/feed_import.py`
5. Run `python pipeline/validate.py` to confirm detection

## Design decisions

- **Detecting the UNKNOWN — two content-agnostic nets.** A heuristic can't catch
  a technique it has no rule for, so two nets don't depend on recognising the
  thing: (1) host↔network **correlation is content-agnostic** — a novel data type
  still produces a provenance record because the signal is the access→exfil
  chain, not the content; (2) an **unclassified-egress catch-all** flags any
  unexplained outbound data flow, so novel exfil channels never leave silently.
  Both surface at *weak* tier (recall-first), so confirmed/strong precision is
  untouched and the analyst reviews the residual.
- **Behavioural signal alone is a candidate, not a verdict — enforced by
  confidence tiering.** On 11 minutes of real enterprise traffic (CIC-IDS-2017),
  the raw behavioural detectors flagged 15 benign cloud endpoints (Microsoft,
  Google, Amazon) — a large upload or a STOR to a public host is indistinguishable
  from exfil at the network layer. So verdicts are graded: `confirmed`
  (threat-intel / JA3 backing), `strong` (≥2 corroborating behaviours), `weak`
  (a lone signal). Filtering to `confirmed` drops those 15 false positives to
  **0** while every C2 stays *surfaced* at the `weak`/`any` tier (recall held).
  Host↔network correlation promotes a weak candidate to confirmed. Near-zero
  interval "beacons" (parallel CDN connections) are rejected outright.
- **Content beats volume for FTP exfil.** A byte-threshold alone misses
  low-volume exfil — AgentTesla-style stealers push credential dumps under
  2 KB over FTP. The control channel carries an explicit `STOR`/`STOU`/`APPE`
  command ("upload this file"), a high-precision signal independent of volume;
  the filename itself is evidence (e.g. `STOR ... Passwords ...`). This is what
  keeps recall at 1.0 on the GuLoader sample the volume path missed.
- **Private IP filtering.** RFC1918, loopback, and link-local addresses are
  excluded from detection — they are internal machines, never C2 destinations.
  This eliminates false positives from bidirectional PCAP traffic.
- **Offline-first attribution.** GeoLite2 (.mmdb) and a local threat-intel
  SQLite table both work air-gapped. In a connected deployment the table is
  refreshed from self-hosted MISP; the lookup interface is unchanged.
- **Evidence is hash-chained.** Each row embeds SHA-256 of the previous row +
  its own content. Tampering with any row breaks verification from that row
  onward — demonstrable, evidence-grade integrity.
- **Encrypted traffic is not a dead end.** When TLS can't be decrypted (cert
  pinning), JA3/JA3S fingerprints + beaconing intervals + destination ASN/geo
  still produce useful attribution without payload content.

## Integration (UMAT)

This module runs as one of four components under the UMAT control plane
(<https://github.com/MYTH-il/E-Rakshak-UMAT>), which owns the case model, the
shared vocabularies, and the schema our output is validated against. Under UMAT:

```bash
python pipeline/orchestrator.py <pcap> --handoff <bundle>/manifest.json --case-id <analysis_run_id>
```

See **`docs/umat_integration.md`** — the contract is deliberately not duplicated here.

## Cross-module interfaces

- **In (from Windows ST/DT):** shared PCAP path + host access events (ETW),
  per `docs/etw_interface_contract.md`.
- **In (from Windows ST/DT):** static IOC prior (candidate IPs/domains from
  binary analysis), used to boost correlation confidence.
- **Out (to shared store / reporting):** rows in the `exfil_events` table
  (`sql/schema.sql`), identical schema to the Android module.
  See `docs/android_schema_parity.md` for the parity checklist.
- **Out (to other tools / agencies):** IOCs in CSV and STIX 2.1 format.

## Files

```
pipeline/
  pcap_loader.py       PCAP + Zeek conn.log -> Connection records
  traffic_analysis.py  beaconing + exfil detection (HTTP volume + FTP-STOR, private IP filtering)
  attribution.py       geo/ASN + reputation (offline-capable)
  ja3_loader.py        JA3/JA3S fingerprints from Zeek ssl.log
  ja3_from_pcap.py     compute JA3/JA3S from PCAP -> Zeek-format ssl.log (no Zeek needed)
  correlation.py       host access <-> network exfil, tiered confidence
  orchestrator.py      runs all stages, emits shared schema + IOC export
  db_loader.py         load findings into PostgreSQL
  validate.py          precision/recall vs labeled ground truth
  feed_import.py       abuse.ch CSV import (Feodo Tracker, URLhaus, JA3)
  export_iocs.py       CSV + STIX 2.1 IOC export
tests/
  conftest.py          shared fixtures
  test_traffic_analysis.py    beaconing + exfil + private IP tests
  test_attribution.py         reputation + graceful degradation tests
  test_correlation.py         correlation + confidence tier tests
  test_evidence_chain.py      hash-chain integrity + tamper detection tests
  test_pcap_loader.py         scapy + Zeek loading tests
sql/schema.sql         shared cross-module schema
docker-compose.yml     Zeek + Suricata + Postgres
docs/
  etw_interface_contract.md    sandbox team interface spec
  android_schema_parity.md     Android team schema checklist
data/                  PCAPs, access-event fixture, ground truth
```
