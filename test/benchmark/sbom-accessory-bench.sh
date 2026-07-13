#!/usr/bin/env bash
# Benchmark for the SCANNER_TRIVY_USE_SBOM_ACCESSORY fast path.
#
# For each image it measures, with the flags the adapter passes to Trivy:
#   1. cold image scan        - trivy image, empty layer cache (today's behavior)
#   2. SBOM generation (cold) - trivy image --format spdx-json (what Harbor's
#                               "Generate SBOM" stores as accessory)
#   3. SBOM scan              - trivy sbom on the generated file (the fast path)
# and verifies that both paths report the same set of vulnerability IDs.
#
# Usage: ./sbom-accessory-bench.sh [image ...]
# Env:   PLATFORM (default linux/amd64), CACHE_DIR, OUT_DIR
set -u

DEFAULT_IMAGES=(
  # node space
  node:18.20.5
  node:18.20.5-alpine
  node:18.20.5-slim
  node:20.18.1
  node:20.18.1-alpine
  node:20.18.1-slim
  node:22.14.0
  node:22.14.0-alpine
  node:22.14.0-slim
  node:23.7.0
  # large-SBOM images
  tensorflow/tensorflow:2.18.0
  apache/airflow:2.10.4
  homeassistant/home-assistant:2025.1.0
  jenkins/jenkins:2.479.3-lts-jdk17
)

IMAGES=("${@:-${DEFAULT_IMAGES[@]}}")
PLATFORM="${PLATFORM:-linux/amd64}"
OUT_DIR="${OUT_DIR:-$(pwd)/sbom-bench-results}"
CACHE_DIR="${CACHE_DIR:-$OUT_DIR/cache}"
SEVERITY="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
COMMON=(--cache-dir "$CACHE_DIR" --no-progress --timeout 30m --skip-db-update --skip-java-db-update)

mkdir -p "$OUT_DIR" "$CACHE_DIR"
CSV="$OUT_DIR/results.csv"
LOG="$OUT_DIR/bench.log"
echo "image,sbom_kb,cold_scan_s,sbom_gen_s,sbom_scan_s,speedup,vulns_image,vulns_sbom,id_diff" > "$CSV"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

now() { python3 -c 'import time; print(time.time())'; }

timed() { # var_name cmd...
  local __var="$1"; shift
  local s e rc
  s=$(now)
  "$@" >>"$LOG" 2>&1
  rc=$?
  e=$(now)
  printf -v "$__var" '%.1f' "$(python3 -c "print($e-$s)")"
  return $rc
}

vuln_ids() { # report.json -> sorted unique "CVE|pkg" lines
  python3 - "$1" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
ids = set()
for res in r.get("Results") or []:
    for v in res.get("Vulnerabilities") or []:
        ids.add(f'{v["VulnerabilityID"]}|{v["PkgName"]}')
print("\n".join(sorted(ids)))
EOF
}

log "trivy: $(trivy --version | head -1), platform: $PLATFORM"
log "downloading vulnerability + Java DBs"
trivy image --download-db-only --cache-dir "$CACHE_DIR" >>"$LOG" 2>&1
trivy image --download-java-db-only --cache-dir "$CACHE_DIR" >>"$LOG" 2>&1

for img in "${IMAGES[@]}"; do
  safe=$(echo "$img" | tr '/:' '__')
  log "=== $img ==="

  trivy clean --scan-cache --cache-dir "$CACHE_DIR" >>"$LOG" 2>&1

  cold=fail
  if ! timed cold trivy image --image-src remote --platform "$PLATFORM" \
      --scanners vuln --severity "$SEVERITY" --vuln-type os,library \
      --format json --output "$OUT_DIR/img_$safe.json" "${COMMON[@]}" "$img"; then
    log "SKIP $img: image scan failed (see $LOG)"
    echo "$img,,,,,,,,SCAN_FAILED" >> "$CSV"
    continue
  fi

  trivy clean --scan-cache --cache-dir "$CACHE_DIR" >>"$LOG" 2>&1

  gen=fail
  timed gen trivy image --image-src remote --platform "$PLATFORM" \
      --format spdx-json --output "$OUT_DIR/sbom_$safe.json" "${COMMON[@]}" "$img" \
    || { log "SKIP $img: SBOM generation failed"; echo "$img,,$cold,,,,,,GEN_FAILED" >> "$CSV"; continue; }

  scan=fail
  timed scan trivy sbom --severity "$SEVERITY" --vuln-type os,library \
      --format json --output "$OUT_DIR/sbomscan_$safe.json" "${COMMON[@]}" "$OUT_DIR/sbom_$safe.json" \
    || { log "SKIP $img: SBOM scan failed"; echo "$img,,$cold,$gen,,,,,SBOM_SCAN_FAILED" >> "$CSV"; continue; }

  sbom_kb=$(( $(stat -f%z "$OUT_DIR/sbom_$safe.json" 2>/dev/null || stat -c%s "$OUT_DIR/sbom_$safe.json") / 1024 ))
  vuln_ids "$OUT_DIR/img_$safe.json" > "$OUT_DIR/ids_img_$safe.txt"
  vuln_ids "$OUT_DIR/sbomscan_$safe.json" > "$OUT_DIR/ids_sbom_$safe.txt"
  vi=$(wc -l < "$OUT_DIR/ids_img_$safe.txt" | tr -d ' ')
  vs=$(wc -l < "$OUT_DIR/ids_sbom_$safe.txt" | tr -d ' ')
  diff_count=$(comm -3 "$OUT_DIR/ids_img_$safe.txt" "$OUT_DIR/ids_sbom_$safe.txt" | grep -c . || true)
  speedup=$(python3 -c "print(f'{$cold/$scan:.1f}x')" 2>/dev/null || echo "n/a")

  log "cold=${cold}s gen=${gen}s sbom_scan=${scan}s speedup=$speedup vulns=$vi/$vs id_diff=$diff_count sbom=${sbom_kb}KB"
  echo "$img,$sbom_kb,$cold,$gen,$scan,$speedup,$vi,$vs,$diff_count" >> "$CSV"
done

log "DONE -> $CSV"
python3 - "$CSV" <<'EOF'
import csv, sys
rows = list(csv.reader(open(sys.argv[1])))
head, data = rows[0], rows[1:]
widths = [max(len(r[i]) for r in rows) for i in range(len(head))]
fmt = lambda r: "| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |"
print(fmt(head)); print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
for r in data: print(fmt(r))
EOF
