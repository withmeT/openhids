#!/usr/bin/env bash
# Apply HIDS Elasticsearch composable index template + ILM policy.
set -euo pipefail

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -n "${ES_USERNAME:-}" && -n "${ES_PASSWORD:-}" ]]; then
  CURL_AUTH=(-u "${ES_USERNAME}:${ES_PASSWORD}")
else
  CURL_AUTH=()
fi

echo "==> PUT ILM policy hids-events-policy"
curl -fsS "${CURL_AUTH[@]}" -X PUT "${ES_URL}/_ilm/policy/hids-events-policy" \
  -H 'Content-Type: application/json' \
  --data-binary @"${ROOT_DIR}/elasticsearch/ilm-policy.json"

echo
echo "==> PUT index template hids-events"
curl -fsS "${CURL_AUTH[@]}" -X PUT "${ES_URL}/_index_template/hids-events" \
  -H 'Content-Type: application/json' \
  --data-binary @"${ROOT_DIR}/elasticsearch/index-template.json"

echo
echo "Done. Ensure hids-server uses ES_DAILY_INDEX=true so indices match hids-events-* / hids-alerts-*."
