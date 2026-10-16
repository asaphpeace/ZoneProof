#!/usr/bin/env bash
# ZoneProof egress worker: one-shot setup for a FRESH, single-purpose Debian/Ubuntu machine (plan steps 7.1 to 7.4).
# Full explanation and the reasons behind each step: BRAND_GUARD_PROBE_WORKER.md.
#
#   sudo bash probe_worker/setup_worker.sh --api https://your-api-host [--key-file FILE | --generate-key]
#   sudo bash probe_worker/setup_worker.sh --uninstall
#
# Run it from the worker package: only probe_worker/ plus app/services/safe_fetch.py and brand_probe_protocol.py (see BRAND_GUARD_PROBE_WORKER.md).
# Never run it from a full copy of backend/: it refuses, because that would put the app's secrets on this machine. It is safe to run again.
# It does, in order: install Docker and Python, create an unprivileged user, install the worker's files read-only, build the renderer image,
# create the renderer's Docker network, add the firewall rules that stop the worker and its containers reaching private networks, TEST those
# rules, and only if the tests pass, start the service. It never prints the key unless you asked it to generate one.
set -euo pipefail

INSTALL_DIR=/opt/zoneproof-worker
VENV_DIR=/opt/zoneproof-worker-venv
ENV_FILE=/etc/zoneproof-worker.env
UNIT_FILE=/etc/systemd/system/zoneproof-worker.service
SVC_USER=zpworker
NETWORK=zp-render
SUBNET=172.30.0.0/24
GATEWAY=172.30.0.1
IMAGE=zoneproof-render:1
# Private, link-local (cloud metadata) and carrier-grade NAT ranges. Loopback is not listed: the host's own resolver may live there.
BLOCKED_V4=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10)
BLOCKED_V6=(fc00::/7 fe80::/10)

API=""; KEY_FILE=""; GENERATE_KEY=0; ALLOW_HTTP=0; SKIP_TESTS=0; UNINSTALL=0; NO_START=0
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --api URL        Base URL of the ZoneProof API the worker calls (https required). It must be the real API address, not behind a proxy that
                   changes the request path: the signature covers the exact path.
  --key-file FILE  File holding the shared signing key (the same value as BRAND_PROBE_KEY on the API).
  --generate-key   Make a new key, store it, and print it ONCE at the end so you can set it on the API.
  (neither)        The key is taken from the ZP_KEY environment variable, or asked for without echo.
  --allow-http     Permit an http:// API URL (testing only).
  --skip-tests     Do not run the firewall self-tests (not recommended).
  --no-start       Install everything but do not start the service.
  --uninstall      Stop the service and remove everything this script installed.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api) API="${2:-}"; shift 2 ;;
    --key-file) KEY_FILE="${2:-}"; shift 2 ;;
    --generate-key) GENERATE_KEY=1; shift ;;
    --allow-http) ALLOW_HTTP=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --no-start) NO_START=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)."

# ── helpers ────────────────────────────────────────────────────────────────────

# ensure_rule CMD ARGS...: add an iptables rule at the top of its chain unless the same rule is already there.
ensure_rule() { local cmd=$1; shift; if ! "$cmd" -w -C "$@" 2>/dev/null; then "$cmd" -w -I "$@"; fi; }
drop_rule()   { local cmd=$1; shift; while "$cmd" -w -C "$@" 2>/dev/null; do "$cmd" -w -D "$@"; done; }

in_blocked_v4() {   # is this IPv4 address inside one of the blocked ranges?
  python3 - "$1" "${BLOCKED_V4[@]}" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(n) for n in sys.argv[2:]) else 1)
PY
}

rule_pkts() {       # rule_pkts CHAIN SOURCE DEST: packet counter of the DROP rule (SOURCE 0.0.0.0/0 for the owner rules)
  iptables -w -vnxL "$1" | awk -v s="$2" -v d="$3" '$3=="DROP" && $8==s && $9==d {print $1; exit}'
}

connects() {        # connects HOST PORT: run as zpworker on the host; exit 0 if a TCP connection opens within 4 seconds
  runuser -u "$SVC_USER" -- python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(4); s.connect((sys.argv[1], int(sys.argv[2])))' "$1" "$2" 2>/dev/null
}

container_connects() {
  docker run --rm --network "$NETWORK" --entrypoint python "$IMAGE" -c 'import socket,sys; s=socket.socket(); s.settimeout(4); s.connect((sys.argv[1], int(sys.argv[2])))' "$1" "$2" 2>/dev/null
}

# ── uninstall ──────────────────────────────────────────────────────────────────

if [[ $UNINSTALL -eq 1 ]]; then
  say "Removing the ZoneProof worker"
  systemctl disable --now zoneproof-worker 2>/dev/null || true
  rm -f "$UNIT_FILE" "$ENV_FILE"; systemctl daemon-reload 2>/dev/null || true
  for net in "${BLOCKED_V4[@]}"; do
    drop_rule iptables DOCKER-USER -s "$SUBNET" -d "$net" -j DROP
    drop_rule iptables OUTPUT -m owner --uid-owner "$SVC_USER" -d "$net" -j DROP
  done
  drop_rule iptables INPUT -s "$SUBNET" -j DROP
  if command -v ip6tables >/dev/null; then for net in "${BLOCKED_V6[@]}"; do drop_rule ip6tables OUTPUT -m owner --uid-owner "$SVC_USER" -d "$net" -j DROP; done; fi
  command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null || true
  docker network rm "$NETWORK" 2>/dev/null || true
  docker image rm "$IMAGE" 2>/dev/null || true
  rm -rf "$INSTALL_DIR" "$VENV_DIR"
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
  echo "Removed. Docker, Python and the firewall package were left installed."
  exit 0
fi

# ── checks before touching anything ────────────────────────────────────────────

[[ -n "$API" ]] || { usage; die "--api is required."; }
[[ "$API" == https://* || ( $ALLOW_HTTP -eq 1 && "$API" == http://* ) ]] || die "the API URL must start with https:// (use --allow-http only for testing)."
API="${API%/}"
command -v apt-get >/dev/null || die "this script supports Debian and Ubuntu (apt) only."
for f in probe_worker/worker.py probe_worker/render_job.py probe_worker/render_policy.py probe_worker/Dockerfile.render probe_worker/zoneproof-worker.service \
         app/services/safe_fetch.py app/services/brand_probe_protocol.py; do
  [[ -f "$SRC/$f" ]] || die "missing $SRC/$f. Run this from the worker package (see BRAND_GUARD_PROBE_WORKER.md), which holds exactly these files."
done
# A full copy of backend/ would put the app's secrets on a machine that fetches hostile pages. Refuse it.
for leak in '.env' '.env.*' 'data' '.venv'; do
  compgen -G "$SRC/$leak" >/dev/null && die "$SRC/$leak is here, so this looks like a full copy of backend/. Send only the worker package (see BRAND_GUARD_PROBE_WORKER.md); never put the app's .env, database settings or data on this machine."
done

KEY=""
if [[ $GENERATE_KEY -eq 1 ]]; then
  KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
elif [[ -n "$KEY_FILE" ]]; then
  [[ -f "$KEY_FILE" ]] || die "key file not found: $KEY_FILE"
  KEY="$(tr -d '[:space:]' < "$KEY_FILE")"
elif [[ -n "${ZP_KEY:-}" ]]; then
  KEY="$ZP_KEY"
else
  read -rsp "Signing key (same as BRAND_PROBE_KEY on the API): " KEY; echo
fi
[[ ${#KEY} -ge 32 ]] || die "the key must be at least 32 characters."
[[ "$KEY" =~ ^[A-Za-z0-9._~+/=-]+$ ]] || die "the key may only contain letters, digits and . _ ~ + / = -"

# ── packages, user, files ──────────────────────────────────────────────────────

say "Installing Docker, Python and the firewall tools"
export DEBIAN_FRONTEND=noninteractive
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get update -qq
apt-get install -y -qq docker.io python3 python3-venv iptables iptables-persistent netfilter-persistent util-linux >/dev/null
systemctl enable --now docker >/dev/null

say "Creating the unprivileged user '$SVC_USER'"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$SVC_USER"
usermod -aG docker "$SVC_USER"
warn "'$SVC_USER' is in the docker group, which is root-equivalent on this machine. That is acceptable only because the machine does nothing else."

say "Installing the worker's files (root-owned and read-only to the worker)"
install -d -m 755 "$INSTALL_DIR/probe_worker" "$INSTALL_DIR/app/services"
for f in worker.py render_job.py render_policy.py Dockerfile.render; do install -m 644 "$SRC/probe_worker/$f" "$INSTALL_DIR/probe_worker/$f"; done
install -m 644 "$SRC/app/services/safe_fetch.py" "$SRC/app/services/brand_probe_protocol.py" "$INSTALL_DIR/app/services/"
: > "$INSTALL_DIR/app/__init__.py"; : > "$INSTALL_DIR/app/services/__init__.py"
chmod 644 "$INSTALL_DIR/app/__init__.py" "$INSTALL_DIR/app/services/__init__.py"
[[ -x "$VENV_DIR/bin/python" ]] || python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet httpx

say "Building the renderer image (a few minutes the first time)"
( cd "$INSTALL_DIR" && docker build -q -f probe_worker/Dockerfile.render -t "$IMAGE" . >/dev/null )

# ── network and firewall ───────────────────────────────────────────────────────

say "Creating the renderer's Docker network ($NETWORK, $SUBNET)"
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  have="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$NETWORK")"
  [[ "$have" == "$SUBNET" ]] || die "network $NETWORK exists with subnet $have, but the firewall rules assume $SUBNET. Remove it (docker network rm $NETWORK) and run again."
else
  docker network create --subnet "$SUBNET" --gateway "$GATEWAY" "$NETWORK" >/dev/null
fi

say "Adding the firewall rules"
for net in "${BLOCKED_V4[@]}"; do
  ensure_rule iptables DOCKER-USER -s "$SUBNET" -d "$net" -j DROP                              # containers cannot go anywhere private
  ensure_rule iptables OUTPUT -m owner --uid-owner "$SVC_USER" -d "$net" -j DROP              # nor can the worker's own light probe
done
ensure_rule iptables INPUT -s "$SUBNET" -j DROP                                               # containers cannot reach this machine
if command -v ip6tables >/dev/null; then
  for net in "${BLOCKED_V6[@]}"; do ensure_rule ip6tables OUTPUT -m owner --uid-owner "$SVC_USER" -d "$net" -j DROP; done
fi

# The worker and the renderer containers still have to resolve names and the worker has to reach the API. Cloud machines (AWS, GCP, Azure) use a DNS
# server on a private address. On Ubuntu /etc/resolv.conf only shows the local stub (127.0.0.53); the real upstream servers are listed in
# /run/systemd/resolve/resolv.conf, so both files are read. Each private DNS server is allowed on port 53 only, for the worker and for the containers
# (without the container rule every render would fail on its first name lookup).
RESOLV_FILES=(/etc/resolv.conf)
[[ -r /run/systemd/resolve/resolv.conf ]] && RESOLV_FILES+=(/run/systemd/resolve/resolv.conf)
while read -r ns; do
  [[ "$ns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
  if in_blocked_v4 "$ns"; then
    for proto in udp tcp; do
      ensure_rule iptables OUTPUT -m owner --uid-owner "$SVC_USER" -d "$ns" -p "$proto" --dport 53 -j ACCEPT
      ensure_rule iptables DOCKER-USER -s "$SUBNET" -d "$ns" -p "$proto" --dport 53 -j ACCEPT
    done
    echo "  allowed DNS lookups (the worker and the renderer containers) to $ns, port 53 only"
  fi
done < <(awk '/^nameserver/ {print $2}' "${RESOLV_FILES[@]}" | sort -u)
read -r API_HOST API_PORT < <(python3 - "$API" <<'PY'
import sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1]); print(u.hostname or "", u.port or (443 if u.scheme == "https" else 80))
PY
)
[[ -n "$API_HOST" ]] || die "could not read a host from $API"
API_IP="$(getent ahostsv4 "$API_HOST" | awk '{print $1; exit}' || true)"
[[ -n "$API_IP" ]] || die "could not resolve $API_HOST from this machine."
if in_blocked_v4 "$API_IP"; then
  ensure_rule iptables OUTPUT -m owner --uid-owner "$SVC_USER" -d "$API_IP" -p tcp --dport "$API_PORT" -j ACCEPT
  warn "the API resolves to a private address ($API_IP): allowed the worker to reach it on port $API_PORT only."
fi
netfilter-persistent save >/dev/null

# ── tests ──────────────────────────────────────────────────────────────────────

FAILED=0
LISTENER=""
trap '[[ -n "$LISTENER" ]] && kill "$LISTENER" 2>/dev/null || true' EXIT          # never leave the test listener behind
if [[ $SKIP_TESTS -eq 0 ]]; then
  say "Testing the firewall (a rule that exists is not the same as a rule that works)"
  check() { if [[ "$2" == ok ]]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s\n' "$1"; FAILED=1; fi; }

  # 1. A container must not reach the machine itself: start a listener on the host and try it through the gateway.
  python3 -m http.server 18080 --bind 0.0.0.0 >/dev/null 2>&1 & LISTENER=$!
  sleep 1
  container_connects "$GATEWAY" 18080 && check "container reaches the host through the gateway" fail || check "container cannot reach the host through the gateway" ok
  kill "$LISTENER" 2>/dev/null || true

  # 2. A container must not reach a private or metadata address: nothing needs to be listening, the DROP rule's packet counter must move.
  before="$(rule_pkts DOCKER-USER "$SUBNET" 169.254.0.0/16)"
  container_connects 169.254.169.254 80 || true
  after="$(rule_pkts DOCKER-USER "$SUBNET" 169.254.0.0/16)"
  [[ "${after:-0}" -gt "${before:-0}" ]] && check "container traffic to the cloud metadata address is dropped" ok || check "container traffic to the cloud metadata address is dropped" fail
  before="$(rule_pkts DOCKER-USER "$SUBNET" 10.0.0.0/8)"
  container_connects 10.255.255.254 80 || true
  after="$(rule_pkts DOCKER-USER "$SUBNET" 10.0.0.0/8)"
  [[ "${after:-0}" -gt "${before:-0}" ]] && check "container traffic to 10.0.0.0/8 is dropped" ok || check "container traffic to 10.0.0.0/8 is dropped" fail

  # 3. The worker's own probe must not reach private addresses either.
  before="$(rule_pkts OUTPUT 0.0.0.0/0 169.254.0.0/16)"
  connects 169.254.169.254 80 || true
  after="$(rule_pkts OUTPUT 0.0.0.0/0 169.254.0.0/16)"
  [[ "${after:-0}" -gt "${before:-0}" ]] && check "the worker's own traffic to the cloud metadata address is dropped" ok || check "the worker's own traffic to the cloud metadata address is dropped" fail

  # 4. Both must still reach the public internet (otherwise the rules are too broad and the worker could never work).
  container_connects 1.1.1.1 443 && check "container can reach the public internet" ok || { warn "could not reach 1.1.1.1:443 from a container (offline test network?)"; }
  connects 1.1.1.1 443 && check "the worker can reach the public internet" ok || { warn "could not reach 1.1.1.1:443 as $SVC_USER (offline test network?)"; }

  # 5. Names must still resolve, from the worker and from inside a container. This is what breaks when a private DNS server (as on AWS) is blocked:
  #    the connection tests above use addresses, not names, and would not notice.
  runuser -u "$SVC_USER" -- python3 -c 'import socket; socket.getaddrinfo("example.com", 443)' 2>/dev/null && check "the worker can resolve names" ok || check "the worker can resolve names" fail
  docker run --rm --network "$NETWORK" --entrypoint python "$IMAGE" -c 'import socket; socket.getaddrinfo("example.com", 443)' 2>/dev/null && check "a container can resolve names" ok || check "a container can resolve names" fail

  if [[ $FAILED -ne 0 ]]; then
    die "a firewall test failed. Nothing was started. Fix the rules (see BRAND_GUARD_PROBE_WORKER.md), then run this script again."
  fi
fi

# ── configuration and service ──────────────────────────────────────────────────

say "Writing the configuration (root-only) and the service"
umask 077
printf 'ZP_API=%s\nZP_KEY=%s\n' "$API" "$KEY" > "$ENV_FILE"
chown root:root "$ENV_FILE"; chmod 600 "$ENV_FILE"
install -m 644 "$SRC/probe_worker/zoneproof-worker.service" "$UNIT_FILE"
systemctl daemon-reload
if [[ $NO_START -eq 1 ]]; then
  systemctl enable zoneproof-worker >/dev/null
  echo "Installed and enabled, not started (--no-start). Start it with: systemctl start zoneproof-worker"
else
  systemctl enable zoneproof-worker >/dev/null
  systemctl restart zoneproof-worker          # (not `enable --now`: that leaves an already-running worker on its old code after a re-run)
  sleep 2
  systemctl is-active --quiet zoneproof-worker && echo "The service is running." || warn "the service is not running: journalctl -u zoneproof-worker -n 50"
fi

say "Done"
cat <<EOF
On the API (its .env), set:
    BRAND_PROBE_ENABLED=true
    BRAND_PROBE_KEY=<the same key as here>
    BRAND_RENDER_ENABLED=true      # optional: the browser. Leave it off to start with the light probe only.
Then restart the API. Check the worker:
    journalctl -u zoneproof-worker -f
    GET /brand-guard/probe-status          (worker_last_seen fills in once it has collected a job)
Rebuild each brand's fingerprint once (Brand profile) so icon and wording comparisons work, then run a scan.
Stop everything at any time by setting BRAND_PROBE_ENABLED=false on the API.
EOF
if [[ $GENERATE_KEY -eq 1 ]]; then
  printf '\nGenerated key (shown once; set it as BRAND_PROBE_KEY on the API, then clear your terminal):\n    %s\n' "$KEY"
fi
