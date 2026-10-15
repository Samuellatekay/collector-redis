#!/usr/bin/env bash
set -uo pipefail

COLLECTOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-/home/haikal/Analisis-Log-by-AI-LLM}"
FILEBEAT_IMAGE="${FILEBEAT_IMAGE:-docker.elastic.co/beats/filebeat:8.17.0}"
BEATS_HOST="${WAZUH_LOGSTASH_HOST:-}"
BEATS_PORT="${WAZUH_LOGSTASH_PORT:-5044}"
IP="38.60.253.35"
LEVEL=12
CONFIRM=0

usage() {
  echo "Usage: $0 --beats-host LOGSTASH_HOST [--beats-port 5044] [--ip PUBLIC_IP] [--level 12-16] --yes"
  echo "  Sends a synthetic Wazuh alert over Beats, then waits for collector, app, and IRIS."
  echo "  This creates one test Indicator, GLPI ticket, and IRIS alert; it sends no traffic to --ip."
  echo "  Set APP_DIR, WAZUH_LOGSTASH_HOST, WAZUH_LOGSTASH_PORT, or FILEBEAT_IMAGE to override defaults."
}

while (($#)); do
  case "$1" in
    --beats-host)
      (($# >= 2)) || { usage >&2; exit 2; }
      BEATS_HOST="$2"
      shift 2
      ;;
    --beats-port)
      (($# >= 2)) || { usage >&2; exit 2; }
      BEATS_PORT="$2"
      shift 2
      ;;
    --ip)
      (($# >= 2)) || { usage >&2; exit 2; }
      IP="$2"
      shift 2
      ;;
    --level)
      (($# >= 2)) || { usage >&2; exit 2; }
      LEVEL="$2"
      shift 2
      ;;
    --yes)
      CONFIRM=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$BEATS_HOST" || "$CONFIRM" != 1 ]]; then
  usage >&2
  echo "Set --beats-host and pass --yes to confirm the test records will be created." >&2
  exit 2
fi
if [[ ! "$BEATS_HOST" =~ ^[A-Za-z0-9._:-]+$ || ! "$BEATS_PORT" =~ ^[0-9]+$ ]] ||
   ((BEATS_PORT < 1 || BEATS_PORT > 65535)); then
  echo "Invalid Beats host or port." >&2
  exit 2
fi
if [[ ! "$LEVEL" =~ ^[0-9]+$ ]] || ((LEVEL < 12 || LEVEL > 16)); then
  echo "Invalid level: current Logstash pipeline requires Wazuh rule level 12-16." >&2
  exit 2
fi
if ! python3 -c 'import ipaddress,sys; ip=ipaddress.IPv4Address(sys.argv[1]); sys.exit(0 if ip.is_global else 1)' "$IP" >/dev/null 2>&1; then
  echo "The test IP must be a public IPv4 address: $IP" >&2
  exit 2
fi
if [[ ! -f "$APP_DIR/docker-compose.yml" || ! -f "$APP_DIR/check_connections.py" ]]; then
  echo "App directory not found or incomplete: $APP_DIR" >&2
  exit 2
fi
if ! command -v docker >/dev/null || ! command -v python3 >/dev/null; then
  echo "Docker and python3 are required on the application server." >&2
  exit 2
fi

COMPOSE_COLLECTOR=(docker compose -f "$COLLECTOR_DIR/docker-compose.yml" --project-directory "$COLLECTOR_DIR")
COMPOSE_APP=(docker compose -f "$APP_DIR/docker-compose.yml" --project-directory "$APP_DIR")
RULE_ID="99$(printf '%04d' "$((RANDOM % 10000))")"
AGENT="pipeline-e2e-$(date -u +%s)-$RANDOM"
TEST_LABEL="PIPELINE-E2E-${RULE_ID}-${RANDOM}"
TEMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

cat > "$TEMP_DIR/alert.json" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)","rule":{"id":"$RULE_ID","level":$LEVEL,"description":"$TEST_LABEL","groups":["intrusion_detection","authentication_failed"]},"agent":{"id":"999","name":"$AGENT"},"manager":{"name":"pipeline-e2e-test"},"data":{"srcip":"$IP","audit":{"res":"failed"}},"full_log":"Synthetic end-to-end pipeline test only; no connection to the source IP was made."}
EOF

cat > "$TEMP_DIR/filebeat.yml" <<EOF
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /test/alert.json
    json.keys_under_root: true
    json.add_error_key: true
    close_eof: true
    scan_frequency: 1s
output.logstash:
  hosts: ["${BEATS_HOST}:${BEATS_PORT}"]
logging.level: info
EOF
chmod 600 "$TEMP_DIR/alert.json" "$TEMP_DIR/filebeat.yml"
chmod 755 "$TEMP_DIR"
chmod 644 "$TEMP_DIR/alert.json" "$TEMP_DIR/filebeat.yml"

echo "=== Preflight: collector Redis/OpenCTI/GLPI ==="
"${COMPOSE_COLLECTOR[@]}" exec -T collector python check_services.py --ip "$IP"
preflight_status=$?
if ((preflight_status != 0)); then
  echo "Collector preflight failed; no test alert was sent." >&2
  exit "$preflight_status"
fi

echo
echo "=== Sending one synthetic Wazuh alert via Beats ${BEATS_HOST}:${BEATS_PORT} ==="
echo "Test label: $TEST_LABEL"
echo "Wazuh rule level: $LEVEL (pipeline routes levels >=12)"
docker run --rm --network host -v "$TEMP_DIR:/test:ro" "$FILEBEAT_IMAGE" \
  -e --strict.perms=false -c /test/filebeat.yml \
  --path.data=/tmp/filebeat-test-data --path.logs=/tmp/filebeat-test-logs --once
if [[ $? != 0 ]]; then
  echo "Filebeat could not send the event. Check Logstash port, network, and Beats TLS settings." >&2
  exit 1
fi

echo
echo "=== Waiting for OpenCTI and GLPI collector results ==="
collector_ok=0
for attempt in $(seq 1 6); do
  collector_output="$("${COMPOSE_COLLECTOR[@]}" exec -T collector \
    python check_services.py --test-label "$TEST_LABEL" 2>&1)"
  printf '%s\n' "$collector_output"
  if grep -q "OpenCTI test.*Indicator uji ditemukan" <<<"$collector_output" &&
     grep -q "GLPI test.*tiket uji ditemukan" <<<"$collector_output"; then
    collector_ok=1
    break
  fi
  if ((attempt < 6)); then sleep 5; fi
done
if ((collector_ok == 0)); then
  echo "OpenCTI Indicator atau GLPI ticket belum terkonfirmasi; lihat log collector dan antrean :failed." >&2
  exit 1
fi

echo
echo "=== Re-enriching the existing OpenCTI observable without resetting its global cursor ==="
refresh_output="$("${COMPOSE_COLLECTOR[@]}" exec -T collector \
  python check_services.py --ip "$IP" --publish-enrichment 2>&1)"
printf '%s\n' "$refresh_output"
if ! grep -q "OpenCTI enrichment.*event diterbitkan ke Redis" <<<"$refresh_output"; then
  echo "OpenCTI enrichment event was not published; the end-to-end test cannot continue." >&2
  exit 1
fi

echo
echo "=== Waiting for the analysis app and IRIS ==="
CHECK_CODE=$(cat <<'PY'
import asyncio, os, sys, time
import asyncpg

label = sys.argv[1]

async def main():
    conn = await asyncpg.connect(os.environ["POSTGRES_DSN"])
    try:
        deadline = time.monotonic() + 60
        last = None
        app_reported = False
        while time.monotonic() < deadline:
            row = await conn.fetchrow("""
                SELECT log_uuid::text, risk_score, ai_status, iris_alert_id,
                       payload #>> '{reputation,opencti_score}' AS opencti_score,
                       payload #>> '{asset,inventory_source}' AS asset_source,
                       jsonb_array_length(COALESCE(
                           payload #> '{enrichment,observables}', '[]'::jsonb
                       )) AS enrichment_count
                FROM log_events
                WHERE payload #>> '{event,action}' = $1
                ORDER BY received_at DESC LIMIT 1
            """, label)
            if row:
                last = row
                if not app_reported:
                    print("Aplikasi: event diterima dari Redis analysis-in; "
                          f"log_uuid={row['log_uuid']} risk={row['risk_score']}", flush=True)
                    app_reported = True
                if row["iris_alert_id"] is not None and row["enrichment_count"] > 0:
                    print("IRIS: alert dibuat "
                          f"id={row['iris_alert_id']} log_uuid={row['log_uuid']}", flush=True)
                    print(f"AI: {row['ai_status']} (tidak ditunggu oleh tes)", flush=True)
                    print(f"Enrichment: {row['enrichment_count']} observable/event terpasang", flush=True)
                    print(f"OpenCTI score pada alert: {row['opencti_score'] or 'belum tersedia'}", flush=True)
                    print(f"GLPI asset pada alert: {row['asset_source'] or 'tidak ditemukan/lookup belum selesai'}", flush=True)
                    return 0
            await asyncio.sleep(2)
        if last:
            print("Aplikasi menerima event, tetapi alur hilir belum lengkap: "
                  f"ai_status={last['ai_status']}, iris_alert_id={last['iris_alert_id']}, "
                  f"enrichment={last['enrichment_count']}. "
                  "Periksa log app, ambang IRIS, serta antrean enrichment-events. "
                  "Status AI tidak menjadi syarat lulus.", flush=True)
        else:
            print("Event belum ditemukan di PostgreSQL aplikasi. "
                  "Periksa output Redis analysis-in di Logstash dan REDIS_LISTS.", flush=True)
        return 1
    finally:
        await conn.close()

raise SystemExit(asyncio.run(main()))
PY
)
"${COMPOSE_APP[@]}" exec -T app python -c "$CHECK_CODE" "$TEST_LABEL"
app_status=$?

echo
echo "=== Recent collector activity ==="
"${COMPOSE_COLLECTOR[@]}" logs --since=5m collector 2>&1 |
  grep -Ei 'outbound-opencti|outbound-glpi|Creating Indicator|GLPI|error' |
  tail -n 40 || true

if ((collector_ok == 1 && app_status == 0)); then
  echo
  echo "END-TO-END TEST PASSED. Remove the test Indicator, GLPI ticket, and IRIS alert when done."
  exit 0
fi

echo
echo "END-TO-END TEST INCOMPLETE. Use the status output above to identify the failing stage."
exit 1
