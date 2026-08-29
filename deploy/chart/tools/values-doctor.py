#!/usr/bin/env python3
"""Advisory checks over a values file.

values.schema.json rejects malformed values, and templates/validate-values.yaml
rejects combinations that cannot work. This catches the third category: values
that are well-formed, render fine, and are still wrong in production.

ERROR findings fail the run. WARN findings are advisory and do not.

Usage: tools/values-doctor.py <values.yaml> [<values.yaml> ...]
"""

import sys

import yaml


def get(values, path, default=None):
    node = values
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return default if node is None else node


# A setting can arrive three ways: the typed value, the config/secret
# passthrough, or extraEnv. Judging only the typed value makes the doctor miss
# exactly the production mistakes it exists to catch.
def effective(values, path, env_name, default=None):
    for source in ("config", "secret"):
        flat = flatten(get(values, source, {}) or {})
        if env_name in flat:
            return flat[env_name]
    for entry in get(values, "extraEnv", []) or []:
        if isinstance(entry, dict) and entry.get("name") == env_name and "value" in entry:
            return entry["value"]
    return get(values, path, default)


def flatten(node, prefix=""):
    """Mirror of the chart's toEnvVars helper: nested maps join with _, upper."""
    out = {}
    if not isinstance(node, dict):
        return out
    for key, value in node.items():
        name = f"{prefix}_{key}".upper() if prefix else str(key).upper()
        if isinstance(value, dict):
            out.update(flatten(value, name))
        elif isinstance(value, list):
            out[name] = ",".join(str(v) for v in value)
        elif value is not None:
            out[name] = str(value)
    return out


def budget_blocks_eviction(budget, replicas, is_min):
    """True when the budget permits zero disruptions.

    Both fields accept an int or a percentage string, so "100%" and "0" are as
    blocking as the integer forms and have to be parsed rather than compared.
    """
    if budget is None or budget == "":
        return False
    if isinstance(budget, str) and budget.strip().endswith("%"):
        try:
            pct = float(budget.strip().rstrip("%"))
        except ValueError:
            return False
        return pct >= 100 if is_min else pct <= 0
    try:
        value = int(budget)
    except (TypeError, ValueError):
        return False
    return value >= replicas if is_min else value <= 0


def check(values):
    """Yield (level, path, message)."""
    findings = []

    def error(path, msg):
        findings.append(("ERROR", path, msg))

    def warn(path, msg):
        findings.append(("WARN", path, msg))

    # The fs scan cache is a single BoltDB file that one process may open at a
    # time, so concurrent workers deadlock or fail rather than share it.
    backend = str(effective(values, "trivy.cacheBackend", "SCANNER_TRIVY_CACHE_BACKEND", "fs"))
    workers = int(effective(values, "jobQueue.workerConcurrency",
                            "SCANNER_JOB_QUEUE_WORKER_CONCURRENCY", 1))
    # A PDB is judged against the replica count that actually applies: under an
    # autoscaler the chart omits replicas entirely and minReplicas is the floor.
    if get(values, "autoscaling.enabled", False):
        replicas = int(get(values, "autoscaling.minReplicas", 1))
    else:
        replicas = int(get(values, "replicaCount", 1))
    if backend in ("", "fs") and workers > 1:
        error(
            "jobQueue.workerConcurrency",
            f"{workers} workers share one fs scan cache, which only one process "
            "may open. Use trivy.cacheBackend memory or a redis:// URL.",
        )

    # Without a volume the DB is re-downloaded on every restart.
    if not get(values, "persistence.enabled", True):
        if not get(values, "trivy.skipUpdate", False):
            warn(
                "persistence.enabled",
                "disabled, so every pod restart re-downloads the Trivy DB. "
                "Expect slow starts and GitHub rate limiting.",
            )

    # skipUpdate without a pre-seeded volume means scanning against nothing.
    if get(values, "trivy.skipUpdate", False):
        # persistence.enabled alone only yields an EMPTY volume; something has
        # to put a database on it.
        seeded = get(values, "persistence.existingClaim") or get(values, "initContainers")
        if not seeded:
            error(
                "trivy.skipUpdate",
                "set with no persistent cache and no initContainers to seed one, "
                "so no vulnerability DB will ever be present.",
            )
        else:
            warn(
                "trivy.skipUpdate",
                "set, so the DB is never refreshed. A stale DB silently produces "
                "stale scan results; make sure something else updates it.",
            )

    # Credentials that end up readable in the pod spec.
    url = str(get(values, "redis.url", ""))
    if not get(values, "redis.existingSecret") and "@" in url.split("//", 1)[-1]:
        warn(
            "redis.url",
            "embeds a password, which lands in the pod spec in clear text. "
            "Use redis.existingSecret.",
        )
    if get(values, "trivy.gitHubToken") and not get(values, "trivy.existingSecret"):
        warn(
            "trivy.gitHubToken",
            "is inlined into the release. Use trivy.existingSecret for anything "
            "longer-lived than a test install.",
        )
    if get(values, "api.tls.key") and not get(values, "api.tls.existingSecret"):
        warn(
            "api.tls.key",
            "inlines a private key into the release. Use api.tls.existingSecret, "
            "which takes a cert-manager Secret directly.",
        )
    if get(values, "imageCredentials.create") and get(values, "imageCredentials.password"):
        warn(
            "imageCredentials.password",
            "is stored in the release. Prefer image.pullSecrets with a Secret "
            "you own.",
        )

    # A budget that can never be satisfied blocks every drain.
    if get(values, "podDisruptionBudget.enabled", False):
        min_available = get(values, "podDisruptionBudget.minAvailable")
        max_unavailable = get(values, "podDisruptionBudget.maxUnavailable")
        if budget_blocks_eviction(min_available, replicas, is_min=True):
            error(
                "podDisruptionBudget.minAvailable",
                f"{min_available} against {replicas} replica(s) leaves no pod "
                "evictable, which blocks node drains indefinitely.",
            )
        if budget_blocks_eviction(max_unavailable, replicas, is_min=False):
            error(
                "podDisruptionBudget.maxUnavailable",
                f"{max_unavailable} leaves no pod evictable, which blocks node "
                "drains indefinitely.",
            )
        if replicas < 2 and not get(values, "autoscaling.enabled", False):
            warn(
                "podDisruptionBudget.enabled",
                f"with replicaCount {replicas} protects nothing.",
            )

    # Scaling below the autoscaler's floor is silently overridden.
    if get(values, "autoscaling.enabled", False):
        min_replicas = int(get(values, "autoscaling.minReplicas", 1))
        if "replicaCount" in values and replicas != min_replicas:
            warn(
                "replicaCount",
                f"{replicas} is ignored while autoscaling is enabled; the "
                f"autoscaler starts from minReplicas {min_replicas}.",
            )

    # Trust settings that defeat each other.
    if get(values, "trivy.insecure", False):
        warn(
            "trivy.insecure",
            "skips registry certificate verification for every scan. If this is "
            "for a private CA, use extraCA instead.",
        )

    # An air-gapped install that still reaches out.
    if get(values, "global.imageRegistry") and not get(values, "trivy.offlineScan", False):
        db = str(get(values, "trivy.dbRepository", "ghcr.io/aquasecurity/trivy-db"))
        if db.startswith("ghcr.io/"):
            warn(
                "trivy.dbRepository",
                "still points at ghcr.io while global.imageRegistry redirects "
                "images to a mirror. The DB download will not be air-gapped.",
            )

    return findings


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    failed = False
    for path in argv[1:]:
        values = yaml.safe_load(open(path)) or {}
        findings = check(values)
        print(f"== {path}", file=sys.stderr)
        if not findings:
            print("   no findings", file=sys.stderr)
        for level, where, message in findings:
            print(f"   {level} {where}: {message}", file=sys.stderr)
            if level == "ERROR":
                failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
