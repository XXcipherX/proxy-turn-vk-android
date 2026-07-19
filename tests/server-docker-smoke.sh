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
    if docker logs "$CONTAINER" 2>&1 | grep -F '[SERVER] Готов' >/dev/null; then
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
    --entrypoint /bin/sh \
    "$IMAGE" \
    -ec '
      wan="$(ip -4 route show default | grep -o "dev [^ ]*" | head -n1 | cut -d" " -f2)"
      comment=WDTT_DOCKER
      subnet=10.66.66.0/24
      iptables -w -I INPUT 1 -i wdtt0 -m comment --comment "$comment" -j DROP
      iptables -w -I FORWARD 1 -i wdtt0 -o wdtt0 -m comment --comment "$comment" -j DROP
      iptables -w -I FORWARD 1 -i wdtt0 -s "$subnet" -o "$wan" -m comment --comment "$comment" -j ACCEPT
      iptables -w -I FORWARD 1 -i "$wan" -o wdtt0 -d "$subnet" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$comment" -j ACCEPT
      iptables -w -I FORWARD 1 -i wdtt0 -m comment --comment "$comment" -j DROP
      iptables -w -I FORWARD 1 -o wdtt0 -m comment --comment "$comment" -j DROP
      iptables -w -t nat -A POSTROUTING -s "$subnet" -o "$wan" -m comment --comment "$comment" -j MASQUERADE
      exec /usr/local/bin/wdtt-server "$@"
    ' wdtt-server \
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
  ext_iface="$(ip -4 route show default | grep -o "dev [^ ]*" | head -n1 | cut -d" " -f2)"
  [ -n "$ext_iface" ]
  iptables -w -t nat -C POSTROUTING -s 10.66.66.0/24 -o "$ext_iface" -m comment --comment WDTT_MANAGED -j MASQUERADE
  iptables -w -C INPUT -i wdtt0 -m comment --comment WDTT_MANAGED -j DROP
  iptables -w -C FORWARD -i wdtt0 -o wdtt0 -m comment --comment WDTT_MANAGED -j DROP
  iptables -w -C FORWARD -i wdtt0 -s 10.66.66.0/24 -o "$ext_iface" -m comment --comment WDTT_MANAGED -j ACCEPT
  iptables -w -C FORWARD -i "$ext_iface" -o wdtt0 -d 10.66.66.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment WDTT_MANAGED -j ACCEPT
  iptables -w -C FORWARD -i wdtt0 -m comment --comment WDTT_MANAGED -j DROP
  iptables -w -C FORWARD -o wdtt0 -m comment --comment WDTT_MANAGED -j DROP
  ! iptables -w -C FORWARD -i wdtt0 -m comment --comment WDTT_MANAGED -j ACCEPT
  ! iptables -w -C FORWARD -o wdtt0 -m comment --comment WDTT_MANAGED -j ACCEPT
  ! iptables-save | grep -Fq WDTT_DOCKER
  [ "$(stat -c %a /etc/wdtt)" = "700" ]
  [ "$(stat -c %a /etc/wdtt/passwords.json)" = "600" ]
  [ "$(stat -c %a /etc/wdtt/wg-keys.dat)" = "600" ]
  [ "$(wc -l < /etc/wdtt/wg-keys.dat)" = "2" ]
'

(
  cd "$SERVER_DIR"
  WDTT_SMOKE_ADDR=127.0.0.1:56000 \
  WDTT_SMOKE_PASSWORD="$PASSWORD" \
    go test -mod=readonly -count=1 -run '^TestRunningServerSurvivesHostileUDP$' -timeout=45s -v .
)

(
  cd "$SERVER_DIR"
  WDTT_SMOKE_ADDR=127.0.0.1:56000 \
  WDTT_SMOKE_PASSWORD="$PASSWORD" \
    go test -mod=readonly -count=1 -run '^TestRunningServerProtocol$' -timeout=45s -v .
)

docker_gateway="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$CONTAINER")"
if ! printf '%s\n' "$docker_gateway" | grep -Eq '^[0-9]+([.][0-9]+){3}$'; then
  echo "Could not determine the container IPv4 gateway" >&2
  exit 1
fi
(
  cd "$SERVER_DIR"
  WDTT_SMOKE_ADDR=127.0.0.1:56000 \
  WDTT_SMOKE_PASSWORD="$PASSWORD" \
  WDTT_SMOKE_HTTP_TARGET="$docker_gateway" \
    go test -mod=readonly -count=1 -run '^TestRunningServerWireGuardDataPlane$' -timeout=90s -v .
)

keys_before="$(docker exec "$CONTAINER" sha256sum /etc/wdtt/wg-keys.dat | awk '{print $1}')"
stop_server_cleanly

exercise_shutdown_phase() {
  local phase="$1"
  local control="$STATE_DIR/shutdown-$phase"
  local test_log="$control.log"
  local test_pid
  rm -f "$control.ready" "$control.release" "$test_log"

  start_server
  (
    cd "$SERVER_DIR"
    WDTT_SMOKE_ADDR=127.0.0.1:56000 \
    WDTT_SMOKE_PASSWORD="$PASSWORD" \
    WDTT_SHUTDOWN_PHASE="$phase" \
    WDTT_SHUTDOWN_CONTROL="$control" \
      go test -mod=readonly -count=1 -run '^TestRunningServerShutdownPhase$' -timeout=45s -v .
  ) >"$test_log" 2>&1 &
  test_pid=$!

  for _ in $(seq 1 300); do
    if [ -f "$control.ready" ]; then
      break
    fi
    if ! kill -0 "$test_pid" 2>/dev/null; then
      cat "$test_log" >&2
      echo "Shutdown client exited before reaching phase $phase" >&2
      return 1
    fi
    sleep 0.1
  done
  if [ ! -f "$control.ready" ]; then
    cat "$test_log" >&2
    echo "Shutdown client did not reach phase $phase" >&2
    return 1
  fi

  local started elapsed exit_code
  started="$(date +%s)"
  docker stop --time 8 "$CONTAINER" >/dev/null
  elapsed=$(( $(date +%s) - started ))
  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER")"
  touch "$control.release"
  if ! wait "$test_pid"; then
    cat "$test_log" >&2
    return 1
  fi
  if [ "$exit_code" != "0" ]; then
    docker logs "$CONTAINER" 2>&1 || true
    echo "Shutdown phase $phase exited with $exit_code, want 0" >&2
    return 1
  fi
  if [ "$elapsed" -gt 7 ]; then
    docker logs "$CONTAINER" 2>&1 || true
    echo "Shutdown phase $phase took ${elapsed}s" >&2
    return 1
  fi
  docker rm "$CONTAINER" >/dev/null
}

sudo grep -Fq 'ci-smoke-device-0001' "$STATE_DIR/passwords.json"
sudo grep -Fq 'ci-e2e-device-0001' "$STATE_DIR/passwords.json"
sudo grep -Fq 'ci-e2e-device-0002' "$STATE_DIR/passwords.json"
docker rm "$CONTAINER" >/dev/null

start_server
keys_after="$(docker exec "$CONTAINER" sha256sum /etc/wdtt/wg-keys.dat | awk '{print $1}')"
if [ "$keys_before" != "$keys_after" ]; then
  echo "WireGuard keys changed after restart" >&2
  exit 1
fi
docker logs "$CONTAINER" 2>&1 | grep -F '[WG] Восстановлено сохранённых устройств: 3' >/dev/null

(
  cd "$SERVER_DIR"
  WDTT_SMOKE_ADDR=127.0.0.1:56000 \
  WDTT_SMOKE_PASSWORD="$PASSWORD" \
    go test -mod=readonly -count=1 -run '^TestRunningServerProtocol$' -timeout=45s -v .
)

stop_server_cleanly

for phase in pre-getconf post-getconf post-ready proxy; do
  exercise_shutdown_phase "$phase"
done
