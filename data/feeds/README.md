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

## Refreshing

Download the feeds on a connected machine, drop them here, and re-run the
import air-gapped:

    python -c "import sys; sys.path.insert(0,'pipeline'); \
      from feed_import import refresh, db_stats; \
      print(refresh('data/feeds')); print(db_stats())"

## Post-import cleaning applied to this snapshot

URLhaus' text feed lists URLs, not indicators, so conversion needs three fixes
that `import_urlhaus` does not make on its own:

1. the CSV header row is otherwise ingested as an indicator (`url`, `dst_ip`);
2. URL hosts that are bare IP addresses arrive typed as `domain` and must be
   reclassified, or an IP will never match an IP lookup;
3. `*.abuse.ch` must be dropped — the feed references its own site, and flagging
   the provider as malicious would be an obvious false positive in a report.

Snapshot after cleaning: 644 indicators (568 IP, 76 domain, 4 JA3).
