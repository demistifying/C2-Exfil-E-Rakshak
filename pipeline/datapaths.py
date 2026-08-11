"""
datapaths.py — resolve bundled data files relative to the MODULE, not the cwd.

Why this exists
---------------
Every runtime data default used to be a bare relative path — "data/threatintel.
sqlite", "data/GeoLite2-City.mmdb", "data/allowlist.json". That works when a
human runs the orchestrator from the repository root, which is how the module
was developed and tested for its whole life.

It does not work in deployment. UMAT's SubprocessC2Runtime launches the
orchestrator with `cwd=<per-run scratch workspace>` and `PYTHONPATH=<staged
module>/pipeline`. The current directory is therefore a temporary directory that
contains no `data/` at all, so every one of those paths resolved to a file that
does not exist and every loader degraded silently to its no-data branch.

Measured under those exact conditions, a known-bad IP came back clean:

    cwd = /tmp/scratch          reputation_hit = False   geo = None
    cwd = <repo root>           reputation_hit = True    geo = BE / EDIS GmbH
                                note = "Redline Stealer C2"

So the threat-intel database has never contributed to a UMAT run. No finding
could reach `confirmed` on reputation, and geo/ASN were empty regardless of
whether the GeoLite2 files were installed. Nothing errored, because absent
intelligence is indistinguishable from a destination that simply is not known
bad — which is exactly the failure mode the honesty gates exist to prevent, and
this one slipped past them.

Resolution order
----------------
1. An explicit argument passed by the caller — always wins.
2. The environment variable, if the caller supports one. Deployments that keep
   evidence outside the module tree must use this: UMAT verifies the staged
   tree with a recursive hash (`effective_tree_sha256`), so writing a database
   or dropping a .mmdb *inside* the promoted directory fails runtime
   verification with a digest mismatch.
3. This module-relative default, which is correct for a normal checkout and for
   anything that ships in `data/`.
"""
from __future__ import annotations

import os

# pipeline/datapaths.py -> pipeline/ -> <module root>
_MODULE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_path(*parts: str) -> str:
    """Absolute path to a file under the module's own data/ directory."""
    return os.path.join(_MODULE_ROOT, "data", *parts)


def resolve(env_var: str, *parts: str) -> str:
    """Environment override if set and non-empty, else the bundled default.

    The environment is read on every call rather than captured at import, so a
    deployment can point at its own location without having to set the variable
    before the module happens to be imported.
    """
    return os.environ.get(env_var) or data_path(*parts)
