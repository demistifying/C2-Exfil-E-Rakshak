# Threat-intelligence feed snapshots

Offline snapshots imported into `data/threatintel.sqlite` via
`pipeline/feed_import.refresh("data/feeds")`. The module never makes live API
calls during analysis — this is what keeps the air-gapped objective true.

| File | Source | Retrieved |
|---|---|---|
| `feodo_ipblocklist.csv` | abuse.ch Feodo Tracker botnet C2 blocklist | 2026-08-10 |
| `urlhaus_online.csv` | abuse.ch URLhaus, online URLs (text feed converted to the CSV columns `import_urlhaus` reads) | 2026-08-10 |

Terms of use: <https://feodotracker.abuse.ch/blocklist/> and
<https://urlhaus.abuse.ch/api/>. abuse.ch feeds are free for non-commercial and
research use; retain this attribution if the database is redistributed.

These snapshots are committed (~210 KB total). They are indicator lists — no
samples, no traffic, no PII, nothing executable — so a fresh clone can rebuild
the database offline without anyone having to source feeds first.

## Seeding a fresh clone

`data/threatintel.sqlite` is a build artifact and is *not* committed. Rebuild it
once after cloning, before any analysis run:

    python scripts/seed_threatintel.py

Skip this and the only indicators present are the three demo seeds in
`attribution.init_threatintel_db()`; every reputation and attribution finding
comes back empty, which looks exactly like the module being broken.

## Refreshing the snapshots

Download the current feeds on a connected machine, replace the files here
(keeping the `feodo*` / `urlhaus*` filename prefixes, which is how `refresh()`
recognises them), then re-run the seeder air-gapped:

    python scripts/seed_threatintel.py --rebuild

## Normalisation applied at import

URLhaus publishes URLs, not indicators, so `import_urlhaus` normalises three
things. These were previously manual post-import cleaning steps recorded only in
this file, which meant `refresh()` rebuilt a subtly wrong database while
appearing to reproduce the shipped one. They are now enforced in code:

1. a bare header row is skipped, rather than stored as an indicator literally
   named `url` (and `dst_ip` for Feodo, which is now guarded by validating that
   the value parses as an address);
2. URL hosts that are bare IP addresses are typed `ip`, not `domain` — roughly
   seven in eight URLhaus hosts are raw addresses, and mistyping them means an
   IP lookup can never match, so the feed contributes nothing;
3. `abuse.ch` and its subdomains are dropped — every row carries a
   `urlhaus_link` back to the site, and flagging the intelligence provider as a
   C2 is a false positive an officer would rightly distrust.

4. hosts belonging to shared hosting, CDN and file-sharing services are dropped
   (`_SHARED_HOSTING`). URLhaus is a *URL* blocklist: when a payload is uploaded
   to a legitimate service, the malicious indicator is the URL, not the host.
   Before this filter the snapshot contained `github.com`,
   `raw.githubusercontent.com`, `drive.google.com`, `www.dropbox.com` and seven
   others, and a benign capture scored `github.com` as **confirmed malicious**
   with the note "malware_download". One such finding in front of a review
   committee discredits every other finding in the report.

Snapshot after normalisation: **634 indicators (567 IP, 63 domain, 4 JA3)**.
`scripts/seed_threatintel.py` fails if the rebuilt total falls below 500, so a
feed-format change is caught loudly instead of leaving a near-empty database.

The shared-hosting list can never be complete, which is the deeper reason a
URL-derived *domain* indicator is weak evidence. The filter removes the worst
offenders; the corroboration rule is what actually stops a lone indicator from
becoming a verdict.
