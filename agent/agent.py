"""patchfirst — installs on a server, collects its stack without root, anonymizes it, and sends it to PatchFirst.

  python3 patchfirst.pyz run [--config /etc/patchfirst.json]   collect and send
  python3 patchfirst.pyz check --api https://example.com [--json]  free check
  python3 patchfirst.pyz dry-run [--config …]                 show what would be sent (sends nothing)
  python3 patchfirst.pyz where [PROJECT] [--config …]       local project path or list
  python3 patchfirst.pyz id [--config …]                    this server's ID in the dashboard
  patchfirst check --ssh user@host --ssh-opt Port=2222 --json  collect over SSH, anonymize locally

The fleet owner provides the config (0600): api, fleet, token (write), secret (labels), identity_words, host,
host_uuid[, ca]. Addresses and server names are not sent to the service: it sees the server's UUID and versions.
Cron: 17 */6 * * * python3 /opt/patchfirst/patchfirst.pyz run >/dev/null
"""
import argparse
from email.utils import parsedate_to_datetime
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import uuid

import anonymize
import collect
import npm_scopes
import catalog
import project_registry
from project_registry import project_state_path, load_projects, save_projects
import uplink

DEFAULT_CONFIG = "/etc/patchfirst.json"
CHECK_TIMEOUT = 300
POLL_INTERVAL = 2
CHECK_ATTEMPTS = 5
COMMON_HOST_WORDS = {
    "web", "app", "db", "server", "host", "node", "master", "worker",
    "debian", "ubuntu", "localhost", "linux", "default", "localdomain",
    "centos", "fedora", "alpine", "rocky", "almalinux", "rhel", "suse",
    "gitlab", "jenkins", "mail",
}
for product in catalog.CATALOG:
    for name in [product["name"]] + product.get("binaries", []):
        COMMON_HOST_WORDS.update(re.split(r"[-._\s]+", name.lower()))
    for pattern in product.get("packages", []):
        COMMON_HOST_WORDS.update(re.findall(r"[a-z][a-z0-9]*", pattern.lower()))
COMMON_HOST_PACKAGES = [re.compile(pattern) for product in catalog.CATALOG
                        for pattern in product.get("packages", [])]


def retry_pause(value, attempt):
    """Retry-After specifies seconds or an HTTP date; the wait is capped at one minute."""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        try:
            seconds = parsedate_to_datetime(value).timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            seconds = 2 * (attempt + 1)
    return max(1, min(60, seconds))


def host_markers(host, inv):
    """Technical names and short name segments do not identify the owner."""
    os_info = inv.get("os", {})
    common = COMMON_HOST_WORDS | {str(os_info.get(k, "")).lower() for k in ("id", "codename")}
    return sorted(word for word in set(re.split(r"[-._]", host.lower()))
                  if len(word) > 3 and word not in common
                  and not any(pattern.fullmatch(word) for pattern in COMMON_HOST_PACKAGES))


def public_addr():
    """Global address on the interfaces (only the public flag is sent, not the address itself)."""
    try:
        out = subprocess.run(["ip", "-j", "addr"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=10, env=collect.child_environment()).stdout
        for link in json.loads(out or b"[]"):
            for a in link.get("addr_info", []):
                if ipaddress.ip_address(a["local"]).is_global:
                    return a["local"]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return ""


def gather(cfg, target=None, ssh_options=()):
    inv = collect.run_ssh(target, options=ssh_options) if target else collect.run_local()
    if inv.get("error"):
        raise uplink.ApiError(inv["error"])
    addr = collect.ssh_address(target, ssh_options) if target else public_addr()
    ports = collect.listener_info(inv)
    inv.update(host=cfg["host"], addr=addr, ports=collect.exposed_ports(addr, ports, bool(target)))
    if target:
        inv["ssh"] = target
    return inv


def configure_public_scopes(api=None, cafile=None):
    # Network failure must keep unknown scopes private; the downloaded artifact is never rewritten.
    npm_scopes.use_service_catalog([])
    if not api:
        return
    try:
        raw = uplink.request(api.rstrip('/') + '/v1/npm-scopes', cafile=cafile, timeout=15, retries=1)
        npm_scopes.use_service_catalog(json.loads(raw))
    except (OSError, ValueError, uplink.ApiError):
        pass


def rejection_reason(error):
    """Rejection reason from the service's JSON response, without control characters."""
    try:
        reason = json.loads(error.read(4096)).get("error")
    except (OSError, ValueError, AttributeError):
        return ""
    if not isinstance(reason, str):
        return ""
    reason = "".join(ch for ch in reason if ch.isprintable())[:200].strip()
    return ": " + reason if reason else ""


def check_call(api, method, path, body=None, key=None, cafile=None, timeout=30):
    """Anonymous check request; the report key is sent only in a header."""
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if key:
        headers["X-PSR-Key"] = key
    try:
        for attempt in range(CHECK_ATTEMPTS):
            try:
                raw = uplink.request(api.rstrip("/") + path,
                                  json.dumps(body, ensure_ascii=False).encode() if body is not None else None,
                                  headers, method=method, cafile=cafile, timeout=timeout, retries=1)
                break
            except urllib.error.HTTPError as e:
                if e.code != 503 or attempt == CHECK_ATTEMPTS - 1:
                    reason = rejection_reason(e)
                    e.close()
                    raise uplink.ApiError("check: API returned %d%s" % (e.code, reason), e.code) from None
                pause = retry_pause(e.headers.get("Retry-After"), attempt)
                e.close()
                time.sleep(pause)
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("invalid response")
        return result
    except (TimeoutError, socket.timeout) as e:
        raise uplink.ApiError("timed out waiting for the service response") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise uplink.ApiError("check service is unavailable or returned an invalid response") from e


def check_payload(target=None, ssh_options=()):
    """One-off inventory with a throwaway label secret; the server name stays here."""
    host = target.rsplit("@", 1)[-1] if target else socket.gethostname()
    cfg = {"host": host, "host_uuid": str(uuid.uuid4()), "secret": secrets.token_urlsafe(32)}
    inv = gather(cfg, target, ssh_options) if target else gather(cfg)
    an = anonymize.Anonymizer(cfg["secret"], host_markers(host, inv))
    return {"inventory": an.payload(inv)}


def print_check_summary(summary):
    print("patchfirst: %d/100 (%s)" % (summary["score"], summary["grade"]))
    highlighted = [row for row in summary.get("components", []) if row["level"] != "clean"]
    for component in highlighted[:5]:
        print("  %s · %s %s" % (component["level"], component["name"], component["version"]))


def check(args):
    configure_public_scopes(args.api, args.ca)
    target = getattr(args, "ssh", None)
    body = check_payload(target, getattr(args, "ssh_opt", ())) if target else check_payload()
    if args.json:
        print(json.dumps(body, ensure_ascii=False, indent=1))
        return 0
    reply = check_call(args.api, "POST", "/v1/check", body, cafile=args.ca)
    try:
        report_id, key = reply["id"], reply["key"]
        if not isinstance(report_id, str) or not isinstance(key, str):
            raise ValueError()
    except (KeyError, ValueError):
        raise uplink.ApiError("check service returned an invalid response")
    url = "%s/check/#%s.%s" % (args.api.rstrip("/"), report_id, key)
    deadline = time.monotonic() + CHECK_TIMEOUT
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise uplink.ApiError("timed out; open the report later")
            reply = check_call(args.api, "GET", "/v1/check/" + report_id, key=key,
                               cafile=args.ca, timeout=min(30, remaining))
            status = reply.get("status")
            if status == "done":
                try:
                    print_check_summary(reply["summary"])
                except (KeyError, TypeError, ValueError) as e:
                    raise uplink.ApiError("check service returned an invalid summary") from e
                return 0
            if status == "error":
                raise uplink.ApiError("analysis failed; try the check again later")
            if status != "pending":
                raise uplink.ApiError("check service returned an invalid status")
            time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))
    finally:
        print(url)


def prepare_payload(config, cfg, inv):
    payload, projects, _ = project_registry.prepare(config, cfg, inv,
                                                   load=load_projects, save=save_projects)
    return payload, projects


def main():
    if sys.argv[1:2] == ["migration-run"]:
        sys.argv = [sys.argv[0]] + sys.argv[4:]
    if sys.argv[1:2] == ["install-commit"]:
        from install_config import commit
        return commit(sys.argv[2:])
    if sys.argv[1:2] == ["install-config"]:
        from install_config import prepare
        return prepare(sys.argv[2:])
    ap = argparse.ArgumentParser(prog="patchfirst", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="patchfirst " + uplink.VERSION)
    ap.add_argument("cmd", choices=("run", "dry-run", "check", "where", "id", "uninstall"))
    ap.add_argument("project", nargs="?", help="project number for the local where command; omit to list projects")
    if os.geteuid() == 0:
        config_paths = (DEFAULT_CONFIG, '/etc/psr-agent.json')
    else:
        config_paths = (os.path.expanduser('~/.local/share/patchfirst/patchfirst.json'),
                        os.path.expanduser('~/.local/share/psr/psr-agent.json'))
    default_config = next((path for path in config_paths if os.path.isfile(path)), config_paths[0])
    ap.add_argument("--config", default=default_config)
    ap.add_argument("--purge", action="store_true", help="also remove local project numbers on uninstall")
    ap.add_argument("--api", help="free check service URL")
    ap.add_argument("--json", action="store_true", help="show anonymized JSON without sending")
    ap.add_argument("--ca", help="trusted CA certificate")
    ap.add_argument("--ssh", metavar="USER@HOST", help="collect over system SSH; only sh is required on the server")
    ap.add_argument("--ssh-opt", action="append", default=[], metavar="OPTION=VALUE",
                    help="ssh -o setting, e.g. Port=2222 or IdentityFile=/path/key (repeatable)")
    args = ap.parse_args()
    if args.purge and args.cmd != 'uninstall':
        ap.error('--purge is only used with uninstall')
    if args.ssh_opt and not args.ssh:
        ap.error("--ssh-opt requires --ssh")
    if args.ssh:
        try:
            collect.ssh_args(args.ssh, args.ssh_opt)
        except ValueError as e:
            ap.error(str(e))
    if args.cmd == "check" and not (args.api or args.json):
        ap.error("check requires --api or --json")
    if args.project and args.cmd != 'where':
        ap.error('project number is only used with where')
    try:
        if args.cmd == 'uninstall':
            from install_config import uninstall
            return uninstall(args.purge)
        if args.cmd == 'where':
            from install_config import runtime_config
            with runtime_config(args.config) as active_config:
                projects = load_projects(active_config)
            rows = sorted(projects.items(), key=lambda item: int(item[1]))
            if args.project:
                rows = [(path, number) for path, number in rows if number == args.project]
                if not rows:
                    raise uplink.ApiError('project not found in the local list; run the run or dry-run command first')
            for path, number in rows:
                print('%s\t%s' % (number, path))
            return 0
        if args.cmd == "check":
            return check(args)
        if args.cmd == "id":
            from install_config import runtime_config
            with runtime_config(args.config) as active_config, open(active_config) as f:
                print(json.load(f)["host_uuid"])
            return 0
        from install_config import runtime_config, reject_legacy_schedule
        with runtime_config(args.config) as active_config:
            if args.cmd == 'run':
                reject_legacy_schedule(active_config)
            with open(active_config) as f:
                cfg = json.load(f)
            configure_public_scopes(cfg.get('api'), cfg.get('ca'))
            inv = gather(cfg, args.ssh, args.ssh_opt) if args.ssh else gather(cfg)
            payload, projects = prepare_payload(active_config, cfg, inv)
        if args.cmd == "dry-run":
            print(json.dumps(payload, ensure_ascii=False, indent=1))
            return 0
        reject_legacy_schedule(active_config)
        link = uplink.Link(cfg["api"], cfg["fleet"], cfg["token"], cfg.get("ca"))
        summary = uplink.upload(link, cfg["host_uuid"], inv, cfg["secret"], cfg.get("identity_words", []),
                                projects=projects)
    except (uplink.ApiError, anonymize.Leak, OSError, ValueError) as e:
        if isinstance(e, uplink.ApiError) and e.status == 402:
            print("patchfirst: server quota exhausted or payment required; open the dashboard", file=sys.stderr)
            return 2
        print("patchfirst: %s" % e, file=sys.stderr)
        return 1
    c = summary["counts"]
    print("patchfirst: %s %d/100 (%s) · P0 %d · P1 %d · P2 %d" % (
        cfg["host"], summary["score"], summary["grade"], c["P0"], c["P1"], c["P2"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
