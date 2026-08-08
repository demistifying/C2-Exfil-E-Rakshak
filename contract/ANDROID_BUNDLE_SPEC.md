# Android Result Bundle — Implementation Spec v1.0

**For:** the Android module team
**Deliverable:** one script that turns an APK into a directory on disk
**Estimated size:** ~100 lines wrapping steps you already run by hand

---

## What this is

The unified tool needs each analysis module to leave its results at a
**predictable path in a predictable shape**. The Windows module already does
this. Android currently doesn't — MobSF keeps everything inside its own
database behind its API, so nothing lands anywhere the rest of the tool can
find it.

This spec defines that drop-off point. Once it exists, everything downstream —
network detection, the shared database, the officer-facing UI — is built by the
integration side without further involvement from you.

---

## What you do NOT need to do

Read this first; it's shorter than the spec.

- **No changes to MobSF.** Drive it over its REST API. Leave the fork alone.
- **No database.** You never connect to Postgres. You write files.
- **No schema, no confidence tiers, no MITRE mapping, no ATT&CK vocabulary.**
  You report raw facts; the integration layer does all interpretation.
- **No C2 / exfiltration detection.** The Windows C2 module's pipeline runs
  against your PCAP and does this. You only need to *capture* the traffic.
- **No report generation.** The unified UI produces the officer-facing report.

Your job is: run the analysis you already run, and drop the outputs in one
directory.

---

## The deliverable

```
/srv/erakshak/handoff/android/{case_id}/
    manifest.json              # required — see below
    hashes.sha256              # required — sha256 of every other file
    static/
        mobsf_report.json      # required — MobSF report JSON, verbatim
    network/
        capture.pcap           # required if dynamic analysis ran
    behavior/
        logcat.txt             # optional
        api_monitor.json       # optional — MobSF Frida API monitor output
    screenshots/
        *.png                  # optional, but high value (see note)
```

`{case_id}` is a UUID passed to your script as an argument. Don't generate it.

**Screenshots are worth prioritising.** The primary users are police officers
with no security training. A picture of what the app actually did on screen is
the single most legible piece of evidence in the whole report.

---

## manifest.json

Every field is required unless marked optional. Types matter; a string `"false"`
is not a boolean `false`.

```json
{
  "schema_version": "1.0",
  "case_id": "3f1a...-uuid-as-passed-in",
  "sample_sha256": "hex, 64 chars",
  "package_name": "com.example.loanapp",

  "status": "completed",
  "status_reason": null,

  "started_at_utc": "2026-08-08T10:14:02Z",
  "ended_at_utc": "2026-08-08T10:21:47Z",

  "device_backend": "avd",
  "android_api_level": 30,

  "static_analysis_completed": true,
  "dynamic_analysis_completed": true,
  "dynamic_run_seconds": 300,

  "emulator_hardened": false,
  "tls_intercepted": true,
  "online_lookups_used": true,

  "artifact_paths": {
    "mobsf_report": "static/mobsf_report.json",
    "pcap": "network/capture.pcap",
    "logcat": "behavior/logcat.txt",
    "api_monitor": "behavior/api_monitor.json",
    "screenshots_dir": "screenshots"
  },

  "tool_versions": {
    "mobsf": "4.x.y",
    "android_api": 30,
    "emulator": "34.x.y"
  }
}
```

### Field notes

**`status`** — one of `completed`, `analysis_error`, `timeout`.
Set `status_reason` to a short human sentence whenever status is not
`completed`. A failed run must still produce a manifest: "the analysis failed
and here is why" is a valid, useful result. Silence is not.

**`dynamic_analysis_completed`** — `false` if you only ran static. The tool
handles static-only cases; it just needs to know, so the report can say
"dynamic analysis was not performed" rather than implying nothing happened.

### The four honesty booleans

These matter more than anything else in the manifest. They are the Android
equivalent of what the Windows module reports about its own limitations, and
they become caveats shown directly to the investigating officer.

| Field | Set `true` when | Why it matters |
|---|---|---|
| `emulator_hardened` | You have applied anti-detection measures to the device | **Set `false` for now.** Stock AVDs and redroid are trivially detectable (`ro.kernel.qemu`, absent telephony stack, redroid build props). Fraud APKs routinely detect emulators and go dormant — so a "nothing happened" result may mean the malware was hiding, not that it's clean. |
| `tls_intercepted` | MobSF's CA was installed and HTTPS was readable | `false` means the app pinned certificates and content was invisible. Detection then falls back to traffic metadata only. |
| `online_lookups_used` | MobSF's domain check or VirusTotal ran | These require internet, which conflicts with the project's offline/air-gapped objective. Report it honestly; the caveat is handled downstream. |

Reporting a limitation is not a failure — an investigator told what the tool
*couldn't* see trusts it far more than one shown an unqualified green tick.

---

## How to produce each artifact

### 1. Static — `static/mobsf_report.json`

Drive MobSF over HTTP. Endpoint names vary slightly by MobSF version — confirm
against your instance's `/api_docs` page:

```
POST /api/v1/upload        (multipart file, header: X-Mobsf-Api-Key)  -> {hash, scan_type, file_name}
POST /api/v1/scan          (hash, scan_type, file_name)
POST /api/v1/report_json   (hash)                                      -> full report
```

Write the response body **verbatim**. Do not filter, reshape, or summarise it —
the integration layer parses it and needs the whole thing. The API key is
printed in MobSF's startup output.

Record MobSF's scan hash in `tool_versions` or alongside `package_name`; it's
the back-reference an analyst uses to open the case in MobSF's own UI.

### 2. Network — `network/capture.pcap`

**This is the highest-value item in the spec and it is one line of change.**

For an AVD, add `-tcpdump` to the launch in `test11.sh`:

```bash
"$EMULATOR_BIN" -avd "$AVD_NAME" \
    -no-snapshot -writable-system \
    -tcpdump "${CAPTURE_DIR}/capture.pcap" \      # <-- add this
    -netdelay none -netspeed full \
    > "$LOGFILE" 2>&1 &
```

For redroid, run `tcpdump` on the host against the container's bridge
interface, filtered to the container IP.

Why it matters: that single file lets the existing Windows C2/exfiltration
pipeline run unmodified against Android traffic — giving beaconing analysis,
JA3/JA4 fingerprinting, DNS tunnelling and DGA detection, covert channels,
ASN/geo attribution, threat-intel correlation and evidence chaining. **None of
which you have to write.** MobSF's HTTP flow log does not substitute: it's
flow-level, and these detectors need packets.

Keep MobSF's HTTP flows as well, if convenient — MobSF installs its own CA, so
those carry decrypted content the PCAP won't have. The two are complementary.

### 3. Behaviour and screenshots

`logcat.txt` via `adb logcat -d`. `api_monitor.json` from MobSF's Frida API
monitor. Screenshots from MobSF's dynamic analyzer, or `adb exec-out screencap`
on a timer.

All optional — ship the bundle without them rather than blocking on them.

### 4. `hashes.sha256`

Standard `sha256sum` format, one line per file, paths relative to the bundle
root. Every file except `hashes.sha256` itself.

```
e3b0c44298fc1c149afbf4c8996fb924...  static/mobsf_report.json
a94a8fe5ccb19ba61c4c0873d391e987...  network/capture.pcap
```

This is the evidentiary integrity record. It must be generated last.

---

## Atomicity — the one hard rule

**Write to a temporary directory, then rename into place.**

```python
tmp = f"/srv/erakshak/handoff/android/.{case_id}.tmp"
final = f"/srv/erakshak/handoff/android/{case_id}"
# ... write everything into tmp ...
os.rename(tmp, final)      # atomic on the same filesystem
```

A worker watches that directory. If it sees a half-written bundle it will
consume a partial case and produce a wrong report. The rename makes the bundle
appear complete or not at all, and the presence of `{case_id}/manifest.json`
*is* the completion signal — you don't need to notify anyone.

The Windows module does exactly this; matching it keeps both sides predictable.

---

## Interface

```bash
./android_analyze.sh <apk_path> <case_id>
```

Exit `0` on success. On failure, still write the bundle with
`status: "analysis_error"` and a `status_reason`, then exit non-zero.

---

## Self-check

You're done when all of these hold for one real APK:

- [ ] `manifest.json` parses and every required field is present with the right type
- [ ] `sample_sha256` matches `sha256sum` of the input APK
- [ ] `static/mobsf_report.json` is MobSF's unmodified response
- [ ] `network/capture.pcap` opens in Wireshark and contains the app's traffic
- [ ] The four honesty booleans reflect what actually happened in the run
- [ ] `hashes.sha256` verifies with `sha256sum -c` from the bundle root
- [ ] The bundle appeared atomically — no partial directory was ever visible
- [ ] A deliberately failed run still produces a manifest with a readable reason

Send one complete bundle for one real APK once those pass. That single bundle
unblocks the entire Android half of the integration — everything downstream can
then be built and tested without waiting on you again.

---

## Open questions to settle first

1. **redroid or AVD?** The README says redroid, `test11.sh` builds an AVD.
   Pick one and drop the other; maintaining two device backends costs more than
   either saves. Whichever you pick, record it in `device_backend`.
2. **How long does dynamic analysis run?** Fraud APKs often delay beaconing.
   Several minutes is more useful than thirty seconds — record the actual value
   in `dynamic_run_seconds`.
