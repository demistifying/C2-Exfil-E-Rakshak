# ETW Access-Event Interface Contract

**Module**: Windows C2/Exfiltration → Windows ST/DT (Sandbox)
**Status**: Awaiting sandbox team implementation
**Version**: 1.0

---

## Purpose

The correlation stage of the C2/Exfiltration module links WHAT the malware
accessed on the host to WHERE it sent data on the network. To do this, it
needs a timeline of host data-access events captured by ETW (Event Tracing
for Windows) during sandbox detonation.

This document defines the **exact JSON schema** the sandbox team must produce.
Until their real ETW output arrives, correlation runs against
`data/access_events_fixture.json`, which matches this schema exactly.
**When real ETW output arrives, nothing in the correlation logic changes —
only the source of the access events.**

---

## Schema

Each access event is a JSON object with these fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `timestamp` | string (ISO 8601) | **Yes** | When the access happened. UTC, microsecond precision preferred. Example: `"2024-10-23T19:15:32.366315+00:00"` |
| `data_type` | string (enum) | **Yes** | What was accessed. See valid values below. |
| `api_call` | string | **Yes** | The ETW-observed API call that performed the access. |
| `process` | string | No | The process name that made the call. Helpful for display but not used in correlation logic. |

### Valid `data_type` values

| Value | Meaning | Typical API calls |
|---|---|---|
| `browser_credentials` | Browser saved passwords / cookies | `CryptUnprotectData`, `BCryptDecrypt` |
| `keystrokes` | Keyboard capture | `SetWindowsHookEx(WH_KEYBOARD_LL)`, `GetAsyncKeyState` |
| `screenshot` | Screen capture | `BitBlt`, `CreateCompatibleBitmap` |
| `clipboard` | Clipboard data | `GetClipboardData`, `OpenClipboard` |
| `crypto_wallet` | Cryptocurrency wallet files | File read from known wallet paths |
| `system_info` | System enumeration | `GetComputerNameExW`, `GetUserNameW` |
| `file_access` | Arbitrary file read | `CreateFileW`, `ReadFile` on sensitive paths |

### Delivery

The access events should be written as a JSON array to a file. The orchestrator
accepts the file path as its second argument:

```bash
python pipeline/orchestrator.py <pcap> <access_events.json>
```

---

## Example

```json
[
  {
    "timestamp": "2024-10-23T19:15:30.366315+00:00",
    "data_type": "browser_credentials",
    "api_call": "CryptUnprotectData",
    "process": "stealer.exe"
  },
  {
    "timestamp": "2024-10-23T19:15:31.000000+00:00",
    "data_type": "keystrokes",
    "api_call": "SetWindowsHookEx(WH_KEYBOARD_LL)",
    "process": "stealer.exe"
  },
  {
    "timestamp": "2024-10-23T19:15:28.500000+00:00",
    "data_type": "screenshot",
    "api_call": "BitBlt",
    "process": "stealer.exe"
  }
]
```

---

## Timing Requirements

- **Clock sync**: The access event timestamps and the PCAP timestamps MUST be
  on the same clock. The correlation engine uses a 15-second time window to
  match access events to subsequent network events. If the clocks are skewed,
  correlation will produce false negatives.
- **UTC**: All timestamps must be UTC (with timezone offset). Local time without
  offset is ambiguous.
- **Precision**: Microsecond precision is preferred (matches PCAP timestamp
  granularity). Second-level precision will work but may produce false positives
  in the correlation window.

---

## Reference Implementation

The fixture file `data/access_events_fixture.json` is the reference
implementation of this contract. If your ETW output matches this schema,
it will work as a drop-in replacement.
