#!/usr/bin/env bash
# Append the per-release artifacthub.io/images annotation to a chart's
# Chart.yaml.
#
# It is not committed because the image tag follows the chart's appVersion, and
# it is appended rather than templated because Chart.yaml deliberately keeps
# `annotations:` as its last top-level key.
#
# Usage: chart-annotate-images.sh <chart-dir> <registry-address> <registry-project>
set -euo pipefail

chart_dir="${1:?chart directory is required}"
registry_address="${2:?registry address is required}"
registry_project="${3:?registry project is required}"
chart_yaml="${chart_dir}/Chart.yaml"

# The append is only correct while `annotations:` is the final top-level key.
# A key added after it would be swallowed into the annotations map - without a
# YAML error, if that key happens to be map-valued - so fail loudly here.
last_key=$(grep -E '^[A-Za-z]' "${chart_yaml}" | tail -1 | cut -d: -f1)
if [[ "${last_key}" != "annotations" ]]; then
  echo "Chart.yaml must keep 'annotations' as its last top-level key (found '${last_key}')." >&2
  exit 1
fi

# Both quote styles are valid YAML here, and a leftover quote would sail through
# into the image tag, so validate the result rather than trust it.
app_version="$(awk -F'[:[:space:]]+' '$1 == "appVersion" { gsub(/["'"'"']/, "", $2); print $2; exit }' "${chart_yaml}")"
if [[ ! "${app_version}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "Unusable appVersion read from ${chart_yaml}: '${app_version}'" >&2
  exit 1
fi

{
  echo "  artifacthub.io/images: |"
  echo "    - name: harbor-scanner-trivy"
  echo "      image: ${registry_address}/${registry_project}/harbor-scanner-trivy:${app_version}"
} >> "${chart_yaml}"

echo "Annotated ${chart_yaml} with images for appVersion ${app_version}"
