# Static IOC Prior — Interface Contract

**Modules:** Windows ST/DT (static/dynamic analysis) → Windows C2/Exfiltration
**Status:** interface built; awaiting ST/DT population
**Version:** 1.0

---

## Purpose & boundary

The C2/Exfiltration module does **not** perform static analysis (unpacking, PE
parsing, YARA, CAPA capability detection, config decryption). That is the ST/DT
module's responsibility. To avoid duplication, ST/DT hands over the **IOCs it
already extracts from the binary** via this contract, and the C2/Exfiltration
module does the one thing that is uniquely its job: **cross-validating those
static IOCs against what was actually observed on the network.**

- A static-extracted C2 that is **also observed** on the wire → **confirmed**
  (binary intent corroborated by observed behaviour — the strongest attribution).
- A static-extracted C2 that is **not observed** → recorded as a **dormant**
  indicator so the case file is complete.

`pipeline/static_prior.py` is the executable reference for this contract.

---

## Schema

A single JSON object:

| Field | Type | Required | Description |
|---|---|---|---|
| `sample_sha256` | string | recommended | SHA-256 of the analysed binary; ties the prior to the case sample. |
| `family` | string | No | Malware family label (e.g. `RedLine Stealer`). |
| `capabilities` | string[] | No | ATT&CK technique ids from CAPA (e.g. `T1555.003`). |
| `c2_indicators` | object[] | **Yes** | The extracted C2/exfil indicators (below). |

Each `c2_indicators` entry:

| Field | Type | Values |
|---|---|---|
| `type` | string | `ip` \| `domain` \| `url` \| `email` |
| `value` | string | the indicator (a URL/email is normalised to its host/domain for matching) |

### Example

```json
{
  "sample_sha256": "9fc244b6ba5c24fe50134870932f6dea852b8fa419ec7cdcf3d84eed70e0e331",
  "family": "AgentTesla-style",
  "capabilities": ["T1555.003", "T1056.001"],
  "c2_indicators": [
    {"type": "ip",     "value": "93.89.225.40"},
    {"type": "url",    "value": "ftp://93.89.225.40/upload/"},
    {"type": "email",  "value": "director@igakuin.com"},
    {"type": "domain", "value": "dormant-backup-c2.example"}
  ]
}
```

---

## Delivery

The orchestrator accepts the prior file path:

```bash
python pipeline/orchestrator.py <pcap> <access_events.json> --static-prior <prior.json>
```

## What the C2/Exfil module does with it

1. **Validates** every indicator (type enum, non-empty value); malformed entries
   are reported, not fatal.
2. **Correlates** each indicator against observed network destinations (IP and
   domain, URL normalised to host).
3. **Promotes** any matching network finding to `confirmed` with the note
   *"matches static-extracted C2 (\<family\>)"*.
4. **Emits** unobserved indicators as `static_ioc` findings (dormant/expected C2).

ST/DT does not need to know anything about the network side — just fill the
prior. If your output validates and the values are correct, correlation works
as a drop-in.
