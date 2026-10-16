"""The worker setup script cannot be run in CI (it needs root, Docker and a fresh machine), so these tests check what can be checked: that it parses,
that its names and paths agree with the code and the service file, that it never prints the key by accident, and that its helper functions behave on
sample data."""
import os
import re
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, ".."))
SCRIPT = os.path.join(BACKEND, "probe_worker", "setup_worker.sh")
UNIT = os.path.join(BACKEND, "probe_worker", "zoneproof-worker.service")
BASH = shutil.which("bash")


def script() -> str:
    return open(SCRIPT, encoding="utf-8").read()


def var(name: str) -> str:
    m = re.search(rf'^{name}=(\S+)$', script(), re.M)
    assert m, name
    return m.group(1).strip('"')


def test_the_script_is_unix_text_with_a_shebang_and_strict_mode():
    raw = open(SCRIPT, "rb").read()
    assert b"\r" not in raw and raw.startswith(b"#!/usr/bin/env bash\n") and b"set -euo pipefail" in raw
    assert b"\r" not in open(UNIT, "rb").read()


@pytest.mark.skipif(BASH is None, reason="bash is not installed")
def test_the_script_parses():
    r = subprocess.run([BASH, "-n", SCRIPT], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_every_file_the_script_installs_exists_in_the_repository():
    needed = re.search(r"for f in (probe_worker/worker\.py.*?); do", script(), re.S).group(1).replace("\\\n", " ").split()
    assert len(needed) >= 7
    for rel in needed:
        assert os.path.isfile(os.path.join(BACKEND, rel)), rel
    for name in re.findall(r"for f in (worker\.py render_job\.py render_policy\.py Dockerfile\.render); do", script())[0].split():
        assert os.path.isfile(os.path.join(BACKEND, "probe_worker", name)), name


def test_names_agree_with_the_worker_the_dockerfile_and_the_service_file():
    from probe_worker import worker
    assert var("NETWORK") == worker.RENDER_NETWORK and var("IMAGE") == worker.RENDER_IMAGE
    unit = open(UNIT, encoding="utf-8").read()
    assert f"User={var('SVC_USER')}" in unit and f"WorkingDirectory={var('INSTALL_DIR')}" in unit and f"EnvironmentFile={var('ENV_FILE')}" in unit
    assert f"ExecStart={var('VENV_DIR')}/bin/python probe_worker/worker.py" in unit
    assert script().count(var("UNIT_FILE")) >= 1 and "zoneproof-worker.service" in var("UNIT_FILE")
    docker = open(os.path.join(BACKEND, "probe_worker", "Dockerfile.render"), encoding="utf-8").read()
    assert f"docker build -f probe_worker/Dockerfile.render -t {var('IMAGE')} ." in docker          # the command in the Dockerfile's header matches
    assert "COPY app/services/safe_fetch.py" in docker and "probe_worker/render_job.py" in docker    # ...and the layout the script installs


def test_a_re_run_restarts_a_running_worker_so_new_files_take_effect():
    # Found on the first real machine: `systemctl enable --now` does nothing to a service that is already running, so two code fixes were
    # copied to disk while the worker kept running the old code in memory, and the script still said "The service is running."
    text = open(SCRIPT, encoding="utf-8").read()
    start_branch = text.split("if [[ $NO_START -eq 1 ]]; then", 1)[1].split("\nfi", 1)[0].split("else", 1)[1]
    commands = "\n".join(line.split("#", 1)[0] for line in start_branch.splitlines())            # (the comment explaining why mentions the old form)
    assert "systemctl restart zoneproof-worker" in commands and "enable --now" not in commands


def test_the_renderer_image_installs_the_playwright_package_at_the_pinned_version():
    # Found on the first real machine: the base image has the browsers but not the Python package, so every render failed with
    # "browser not installed". The package version must also match the browsers the base image ships.
    docker = open(os.path.join(BACKEND, "probe_worker", "Dockerfile.render"), encoding="utf-8").read()
    pinned = re.search(r"^playwright==([\d.]+)", open(os.path.join(BACKEND, "requirements.txt"), encoding="utf-8").read(), re.M).group(1)
    assert re.search(r"pip install[^\n]*\bplaywright==" + re.escape(pinned) + r"\b", docker)
    assert f"playwright/python:v{pinned}-" in docker


def test_the_blocked_ranges_cover_what_the_runbook_and_the_renderer_policy_refuse():
    m = re.search(r"BLOCKED_V4=\(([^)]*)\)", script())
    ranges = set(m.group(1).split())
    assert {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} <= ranges
    assert var("SUBNET") == "172.30.0.0/24" and var("GATEWAY") == "172.30.0.1"
    from probe_worker import render_policy as rp                            # (the renderer refuses the same ranges by address, as a second layer)
    for probe in ("10.1.2.3", "172.16.5.5", "192.168.1.1", "169.254.169.254"):
        assert rp.allow_request("GET", f"http://{probe}/")[0] is False
    assert "fc00::/7" in script() and "fe80::/10" in script()


def test_the_unit_holds_no_secret_and_is_sandboxed():
    unit = open(UNIT, encoding="utf-8").read()
    assert "ZP_KEY=" not in unit and "ZP_API=" not in unit
    for needed in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "Restart=always", "SupplementaryGroups=docker"):
        assert needed in unit, needed


def test_the_key_is_never_echoed_and_is_only_printed_when_it_was_generated():
    s = script()
    assert not re.search(r'(echo|printf)[^\n]*\$\{?ZP_KEY', s.replace("printf 'ZP_API=%s\\nZP_KEY=%s\\n'", ""))
    assert not re.search(r'echo\s+"?\$\{?KEY\}?', s)
    printed = [i for i in re.finditer(r'printf [^\n]*\$KEY|printf [^\n]*"\$KEY"', s)]
    assert len(printed) == 2                                                      # the environment file and the one-off generated-key message
    tail = s[s.index("Generated key"):]
    assert "GENERATE_KEY" in s[s.rindex("if [[ $GENERATE_KEY -eq 1 ]]; then"):]  # the message sits inside the --generate-key branch
    assert "chmod 600" in s and 'umask 077' in s


def test_a_private_dns_server_is_allowed_for_the_worker_and_the_containers_and_name_resolution_is_tested():
    s = script()
    assert "/run/systemd/resolve/resolv.conf" in s                                        # Ubuntu's real upstream servers, not just the 127.0.0.53 stub
    assert re.search(r'ensure_rule iptables DOCKER-USER -s "\$SUBNET" -d "\$ns" -p "\$proto" --dport 53 -j ACCEPT', s)       # the containers' lookups
    assert re.search(r'ensure_rule iptables OUTPUT -m owner --uid-owner "\$SVC_USER" -d "\$ns" -p "\$proto" --dport 53 -j ACCEPT', s)
    assert "can resolve names" in s and s.count("socket.getaddrinfo") == 2                # tested from the worker and from a container, by name
    # the exception is port 53 only and only for a server that is actually on a blocked range: no blanket allow of a private network
    block = s[s.index("RESOLV_FILES=("):s.index("API_HOST API_PORT")]
    assert "in_blocked_v4" in block and block.count("-j ACCEPT") == 2 and "--dport 53" in block
    assert s.index("ensure_rule iptables DOCKER-USER -s \"$SUBNET\" -d \"$net\" -j DROP") < s.index('ensure_rule iptables DOCKER-USER -s "$SUBNET" -d "$ns"')     # exceptions sit above the drops


@pytest.mark.skipif(BASH is None, reason="bash is not installed")
def test_the_resolver_list_reads_both_files_and_survives_a_missing_one(tmp_path):
    a, b = tmp_path / "a.conf", tmp_path / "b.conf"
    a.write_text("nameserver 127.0.0.53\noptions edns0\n")
    b.write_text("# upstream\nnameserver 10.50.0.2\nnameserver 10.50.0.2\nnameserver 169.254.169.253\n")
    snippet = "RESOLV_FILES=(" + str(a).replace("\\", "/") + ")\n[[ -r " + str(b).replace("\\", "/") + " ]] && RESOLV_FILES+=(" + str(b).replace("\\", "/") + ")\n" + \
              "awk '/^nameserver/ {print $2}' \"${RESOLV_FILES[@]}\" | sort -u\n"
    out = subprocess.run([BASH, "-c", "set -euo pipefail\n" + snippet], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.split() == ["10.50.0.2", "127.0.0.53", "169.254.169.253"]
    missing = snippet.replace(str(b).replace("\\", "/"), str(tmp_path / "nope.conf").replace("\\", "/"))
    out = subprocess.run([BASH, "-c", "set -euo pipefail\n" + missing], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.split() == ["127.0.0.53"]                  # a missing file does not stop the script under `set -e`


def test_the_script_refuses_a_full_backend_copy_and_the_package_command_contains_only_worker_files(tmp_path):
    s = script()
    assert "for leak in '.env' '.env.*' 'data' '.venv'; do" in s and "never put the app's .env" in s        # quoted: unquoted, the shell would expand .env.* against the current folder
    doc = open(os.path.join(BACKEND, "..", "BRAND_GUARD_PROBE_WORKER.md"), encoding="utf-8").read()
    cmd = re.search(r"tar -czf zp-worker\.tgz[^\n]*", doc).group(0)
    assert "probe_worker" in cmd and "safe_fetch.py" in cmd and "brand_probe_protocol.py" in cmd and "--exclude=__pycache__" in cmd
    for forbidden in (".env", "data", ".venv", "alembic", "tests"):
        assert forbidden not in cmd.replace("--exclude=__pycache__", ""), forbidden
    assert "Never copy the whole `backend/` folder" in doc and "Copy the `backend/` folder over" not in doc


@pytest.mark.skipif(BASH is None, reason="bash is not installed")
def test_the_refusal_fires_when_an_env_file_or_data_folder_sits_next_to_the_worker_files(tmp_path):
    for leak, make in ((".env", lambda p: p.write_text("SECRET=1")), ("data", lambda p: p.mkdir()), (".venv", lambda p: p.mkdir()), (".env.production", lambda p: p.write_text("x"))):
        root = tmp_path / leak.replace(".", "_")
        root.mkdir()
        make(root / leak)
        guard = re.search(r"for leak in '\.env' '\.env\.\*' 'data' '\.venv'; do.*?\ndone", script(), re.S).group(0)
        prog = f'SRC="{str(root).replace(chr(92), "/")}"\ndie() {{ echo "DIED: $*"; exit 7; }}\n{guard}\necho clean\n'
        r = subprocess.run([BASH, "-c", prog], capture_output=True, text=True)
        assert r.returncode == 7 and "full copy of backend/" in r.stdout, (leak, r.stdout, r.stderr)
    clean = tmp_path / "clean"
    clean.mkdir()
    prog = f'SRC="{str(clean).replace(chr(92), "/")}"\ndie() {{ echo "DIED: $*"; exit 7; }}\n{guard}\necho clean\n'
    r = subprocess.run([BASH, "-c", prog], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "clean"


def test_refusals_and_defaults_are_in_place():
    s = script()
    assert "must start with https://" in s and "--allow-http" in s                 # plain http only on request
    assert "at least 32 characters" in s and "run as root" in s
    assert "Nothing was started" in s                                              # a failed firewall test stops the service from starting
    assert re.search(r"if \[\[ \$FAILED -ne 0 \]\]; then\s+die", s)


def _function(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{.*?^\}}$", script(), re.S | re.M)
    assert m, name
    return m.group(0)


@pytest.mark.skipif(BASH is None, reason="bash is not installed")
def test_the_counter_reader_picks_the_right_rule_from_iptables_output():
    sample = (
        "Chain DOCKER-USER (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "       4      240 DROP       0    --  *      *       172.30.0.0/24        169.254.0.0/16\n"
        "      17     1020 DROP       0    --  *      *       172.30.0.0/24        10.0.0.0/8\n"
        "     900    54000 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0\n"
        "Chain OUTPUT (policy ACCEPT)\n"
        "       2      120 DROP       0    --  *      *       0.0.0.0/0            169.254.0.0/16       OWNER UID match 998\n"
    )
    prog = f"iptables() {{ printf '%s' '{sample}'; }}\n{_function('rule_pkts')}\n"
    def run(args):
        r = subprocess.run([BASH, "-c", prog + f"rule_pkts {args}"], capture_output=True, text=True)
        return r.stdout.strip()
    assert run("DOCKER-USER 172.30.0.0/24 169.254.0.0/16") == "4"
    assert run("DOCKER-USER 172.30.0.0/24 10.0.0.0/8") == "17"
    assert run("OUTPUT 0.0.0.0/0 169.254.0.0/16") == "2"
    assert run("DOCKER-USER 172.30.0.0/24 192.168.0.0/16") == ""                    # no such rule: empty, which the tests treat as zero


def _bash_python3_works() -> bool:
    """True only if `python3` inside bash really runs Python (on Windows it can be the Microsoft Store placeholder, which exists but does nothing)."""
    if BASH is None:
        return False
    r = subprocess.run([BASH, "-c", "python3 -c 'print(40 + 2)'"], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "42"


@pytest.mark.skipif(not _bash_python3_works(), reason="a working python3 inside bash is needed")
def test_the_private_address_check_classifies_addresses():
    prog = "BLOCKED_V4=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10)\n" + _function("in_blocked_v4") + "\n"
    def blocked(ip):
        return subprocess.run([BASH, "-c", prog + f"in_blocked_v4 {ip}"], capture_output=True).returncode == 0
    for ip in ("10.0.0.2", "172.20.1.1", "192.168.0.10", "169.254.169.254", "100.100.100.100"):
        assert blocked(ip), ip
    for ip in ("1.1.1.1", "8.8.8.8", "172.32.0.1", "93.184.216.34", "127.0.0.53"):
        assert not blocked(ip), ip
