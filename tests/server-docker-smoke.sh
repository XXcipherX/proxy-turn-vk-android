#!/usr/bin/env bash
set -Eeuo pipefail

IMAGE="${WDTT_SMOKE_IMAGE:-wdtt-server-ci:local}"
CONTAINER="${WDTT_SMOKE_CONTAINER:-wdtt-server-ci}"
PASSWORD="${WDTT_SMOKE_PASSWORD:-CI-Smoke_7kM9xQ2}"
STATE_DIR="${RUNNER_TEMP:-/tmp}/wdtt-server-smoke-${GITHUB_RUN_ID:-$$}"
SERVER_DIR="app/src/main/assets/linux-server"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if command -v sudo >/dev/null 2>&1; then
    sudo rm -rf "$STATE_DIR"
  else
    rm -rf "$STATE_DIR"
  fi
}
trap cleanup EXIT

wait_ready() {
  for _ in $(seq 1 60); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != "true" ]; then
      docker logs "$CONTAINER" 2>&1 || true
      echo "WDTT container exited before readiness" >&2
      return 1
    fi
    if docker logs "$CONTAINER" 2>&1 | grep -Fq '[SERVER] Готов'; then
      return 0
    fi
    sleep 1
  done
  docker logs "$CONTAINER" 2>&1 || true
  echo "WDTT container did not become ready" >&2
  return 1
}

start_server() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$CONTAINER" \
    --privileged \
    -p 127.0.0.1:56000:56000/udp \
    -v "$STATE_DIR:/etc/wdtt" \
    "$IMAGE" \
    -listen=0.0.0.0:56000 \
    -wg-port=56001 \
    -config-dir=/etc/wdtt \
    -password="$PASSWORD" \
    -max-connections=32 \
    -handshake-rate=16 >/dev/null
  wait_ready
}

stop_server_cleanly() {
  docker stop --time 20 "$CONTAINER" >/dev/null
  local exit_code
  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER")"
  if [ "$exit_code" != "0" ]; then
    docker logs "$CONTAINER" 2>&1 || true
    echo "WDTT container exit code is $exit_code, want 0" >&2
    return 1
  fi
}

if [ ! -c /dev/net/tun ]; then
  sudo modprobe tun || true
fi
if [ ! -c /dev/net/tun ]; then
  echo "/dev/net/tun is unavailable on the runner" >&2
  exit 1
fi

mkdir -p "$STATE_DIR"
docker build --pull -t "$IMAGE" .

start_server

docker exec "$CONTAINER" sh -exc '
  [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]
  ip -4 addr show wdtt0 | grep -Fq "10.66.66.1/24"
  ss -H -lun | grep -Eq "127[.]0[.]0[.]1:56001([[:space:]]|$)"
  ! ss -H -lun | grep -Eq "(0[.]0[.]0[.]0|\[::\]):56001([[:space:]]|$)"
  ss -H -lun | grep -Eq "(\\*|0[.]0[.]0[.]0|\\[::\\]):56000([[:space:]]|$)"
  iptables -w -t nat -S POSTROUTING | grep -F "10.66.66.0/24" | grep -Fq "WDTT_MANAGED"
  iptables -w -S FORWARD | grep -F -- "-i wdtt0" | grep -Fq "WDTT_MANAGED"
  iptables -w -S FORWARD | grep -F -- "-o wdtt0" | grep -Fq "WDTT_MANAGED"
  [ "$(stat -c %a /etc/wdtt)" = "700" ]
  [ "$(stat -c %a /etc/wdtt/passwords.json)" = "600" ]
  [ "$(stat -c %a /etc/wdtt/wg-keys.dat)" = "600" ]
'

(
  cd "$SERVER_DIR"
  WDTT_SMOKE_ADDR=127.0.0.1:56000 \
  WDTT_SMOKE_PASSWORD="$PASSWORD" \
    go test -mod=readonly -count=1 -run '^TestRunningServerProtocol$' -timeout=45s -v .
)

keys_before="$(docker exec "$CONTAINER" sha256sum /etc/wdtt/wg-keys.dat | awk '{print $1}')"
stop_server_cleanly
sudo grep -Fq 'ci-smoke-device-0001' "$STATE_DIR/passwords.json"
docker rm "$CONTAINER" >/dev/null

start_server
keys_after="$(docker exec "$CONTAINER" sha256sum /etc/wdtt/wg-keys.dat | awk '{print $1}')"
if [ "$keys_before" != "$keys_after" ]; then
  echo "WireGuard keys changed after restart" >&2
  exit 1
fi
docker logs "$CONTAINER" 2>&1 | grep -Fq '[WG] Восстановлено сохранённых устройств: 1'

(
  cd "$SERVER_DIR"
  WDTT_SMOKE_ADDR=127.0.0.1:56000 \
  WDTT_SMOKE_PASSWORD="$PASSWORD" \
    go test -mod=readonly -count=1 -run '^TestRunningServerProtocol$' -timeout=45s -v .
)

stop_server_cleanly
