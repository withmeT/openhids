#!/usr/bin/env bash
# Replay failed bulk NDJSON batches from SPOOL_DIR back to Elasticsearch.
set -euo pipefail

SPOOL_DIR="${SPOOL_DIR:-./spool-server}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_INDEX="${ES_INDEX:-hids-events}"
ES_DAILY_INDEX="${ES_DAILY_INDEX:-true}"

if [[ -n "${ES_USERNAME:-}" && -n "${ES_PASSWORD:-}" ]]; then
  CURL_AUTH=(-u "${ES_USERNAME}:${ES_PASSWORD}")
else
  CURL_AUTH=()
fi

if [[ ! -d "${SPOOL_DIR}" ]]; then
  echo "spool directory not found: ${SPOOL_DIR}" >&2
  exit 1
fi

shopt -s nullglob
files=("${SPOOL_DIR}"/*.ndjson "${SPOOL_DIR}"/*.bulk)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "no spool files in ${SPOOL_DIR}"
  exit 0
fi

index="${ES_INDEX}"
if [[ "${ES_DAILY_INDEX}" == "true" || "${ES_DAILY_INDEX}" == "1" ]]; then
  day="$(date -u +%Y.%m.%d)"
  index="${ES_INDEX}-${day}"
fi

for f in "${files[@]}"; do
  echo "==> replay ${f} -> ${ES_URL}/${index}/_bulk"
  if curl -fsS "${CURL_AUTH[@]}" -X POST "${ES_URL}/${index}/_bulk" \
    -H 'Content-Type: application/x-ndjson' \
    --data-binary @"${f}"; then
    rm -f "${f}"
    echo " ok (removed spool file)"
  else
    echo " failed, keeping ${f}" >&2
    exit 1
  fi
done

echo "replay complete"
