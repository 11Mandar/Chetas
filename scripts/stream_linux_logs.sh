#!/usr/bin/env bash
# ==============================================================================
# Chetas ULPF — Real-time Linux Log Streaming Shipper
# Streams authentic Linux journal & auth events directly to Chetas Command Center
# ==============================================================================

CHETAS_SERVER_IP="${1:-10.180.250.129}"
CHETAS_PORT="${2:-3000}"
CHETAS_URL="http://${CHETAS_SERVER_IP}:${CHETAS_PORT}"

# Automatically discover local IPv4 address
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
fi
if [ -z "$LOCAL_IP" ]; then
  LOCAL_IP="127.0.0.1"
fi

HOSTNAME=$(hostname)
DISTRO="Linux"
if [ -f /etc/os-release ]; then
  DISTRO=$(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release || echo "Linux")
fi

echo "================================================================"
echo " Chetas ULPF — Real-time Linux Telemetry Shipper"
echo " Host:        ${HOSTNAME} (${DISTRO})"
echo " Source IP:   ${LOCAL_IP}"
echo " Destination: ${CHETAS_SERVER_IP}:${CHETAS_PORT}"
echo " Endpoint:    ${CHETAS_URL}/api/logs/ingest"
echo "================================================================"

# Check connectivity
if ! curl -s -m 3 "${CHETAS_URL}/api/status" > /dev/null; then
  echo -e "\n[Warning] Cannot reach Chetas at ${CHETAS_URL} yet. Retrying in background...\n"
fi

# Determine best log source: journalctl > /var/log/auth.log > /var/log/syslog
if command -v journalctl > /dev/null 2>&1; then
  LOG_CMD="sudo journalctl -f -n 10 --no-pager"
elif [ -f /var/log/auth.log ]; then
  LOG_CMD="sudo tail -F -n 10 /var/log/auth.log"
elif [ -f /var/log/syslog ]; then
  LOG_CMD="sudo tail -F -n 10 /var/log/syslog"
else
  LOG_CMD="sudo dmesg -w"
fi

echo "Monitoring stream: ${LOG_CMD}"
echo "Press Ctrl+C to stop streaming."
echo "----------------------------------------------------------------"

eval "${LOG_CMD}" | while IFS= read -r line; do
  [ -z "$line" ] && continue

  # Escape special characters for JSON safety
  SAFE_MSG=$(python3 -c "import json, sys; print(json.dumps(sys.stdin.read().strip()))" <<< "$line" 2>/dev/null)
  if [ -z "$SAFE_MSG" ]; then
    SAFE_MSG=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g')
    SAFE_MSG="\"${SAFE_MSG}\""
  fi

  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  PAYLOAD=$(cat <<EOF
{
  "source_ip": "${LOCAL_IP}",
  "destination_ip": "${CHETAS_SERVER_IP}",
  "source_host": "${HOSTNAME}",
  "vendor": "${DISTRO}",
  "product": "Remote-Linux-${HOSTNAME}",
  "event_type": "SYSTEM_LOG",
  "level": "Information",
  "timestamp": "${TIMESTAMP}",
  "message": ${SAFE_MSG}
}
EOF
)

  RESPONSE=$(curl -s -X POST "${CHETAS_URL}/api/logs/ingest" \
    -H "Content-Type: text/plain" \
    -H "x-source-id: src-linux-${HOSTNAME}" \
    -d "$PAYLOAD" 2>&1)

  if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "[Ingested] ${LOCAL_IP} -> ${CHETAS_SERVER_IP} | ${line:0:70}..."
  else
    echo "[Waiting] Attempting to deliver to Chetas..."
  fi
done
