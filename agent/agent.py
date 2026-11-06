"""patchfirst - installs on a server, collects its stack without root, pseudonymizes it, and sends it to PatchFirst.

  python3 patchfirst.pyz run [--config /etc/patchfirst.json]   collect and send
  python3 patchfirst.pyz check --api https://example.com [--json]  free check
  python3 patchfirst.pyz dry-run [--config ...]                 show what would be sent (sends nothing)
  python3 patchfirst.pyz where [PROJECT] [--config ...]       local project path or list
  python3 patchfirst.pyz id [--config ...]                    this server's ID in the dashboard
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
import agent_messages
from agent_messages import t
import collect
import catalog
import project_registry
import public_package_names
from project_registry import project_state_path, load_projects, save_projects
import uplink

DEFAULT_CONFIG = "/etc/patchfirst.json"
CHECK_TIMEOUT = 300
POLL_INTERVAL = 2
PROGRESS_INTERVAL = 10
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
        message = inv['error']
        timeout = re.fullmatch(r'ssh timeout (\d+) s', message)
        exit_code = re.fullmatch(r'ssh exit code (\d+)', message)
        if timeout:
            message = t('SSH timed out after {seconds} s', seconds=timeout[1])
        elif exit_code:
            message = t('SSH exited with code {code}', code=exit_code[1])
        elif message == 'collection failed':
            message = t('Collection failed')
        raise uplink.ApiError(message)
    addr = collect.ssh_address(target, ssh_options) if target else public_addr()
    ports = collect.listener_info(inv)
    inv.update(host=cfg["host"], addr=addr, ports=collect.exposed_ports(addr, ports, bool(target)))
    if target:
        inv["ssh"] = target
    return inv


def configure_public_scopes(api=None, cafile=None, cache=None, offline=False, fallback=False, needed=()):
    # Retain the entry point name for local callers; identities use only this list.
    if api:
        return public_package_names.load(api, cache, cafile=cafile, offline=offline, fallback=fallback, needed=needed)
    public_package_names.use(None)


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
                    raise uplink.ApiError(t("check: API returned {status}{reason}", status=e.code, reason=reason), e.code) from None
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


def check_payload(target=None, ssh_options=(), inventory=None):
    """One-off inventory with a throwaway label secret; the server name stays here."""
    host = target.rsplit("@", 1)[-1] if target else socket.gethostname()
    cfg = {"host": host, "host_uuid": str(uuid.uuid4()), "secret": secrets.token_urlsafe(32)}
    inv = inventory
    if inv is None:
        inv = gather(cfg, target, ssh_options) if target else gather(cfg)
    an = anonymize.Anonymizer(cfg["secret"], host_markers(host, inv))
    return {"inventory": an.payload(inv)}


def rating_text(summary):
    """Display authoritative fields; standalone agents never calculate ratings."""
    unknown = {'score': None, 'grade': '?'}
    ratings = summary.get('ratings') or {
        'external': unknown, 'local': unknown,
        'global': {'score': summary.get('score'), 'grade': summary.get('grade', '?')},
        'expected': {'score': summary.get('global_score'), 'grade': summary.get('global_grade', '?')}}
    labels = [('external', t('External')), ('local', t('Local')), ('global', t('Global')),
              ('expected', t('Expected') + '*')]
    parts = []
    for key, label in labels:
        entry = ratings.get(key) or unknown
        value = (t('{score}/100 ({grade})', score=entry['score'], grade=entry['grade'])
                 if entry.get('score') is not None and entry.get('grade', '?') != '?' else '?')
        parts.append(label + ': ' + value)
    return parts[0] + '\n  ' + ' - '.join(parts[1:]) + '\n' + t(
        '* Expected: if reported risks are confirmed, allowing for unchecked software.')


def print_check_summary(summary):
    print(t("patchfirst: {message}", message=rating_text(summary)))
    highlighted = [row for row in summary.get("components", []) if row["level"] != "clean"]
    for component in highlighted[:5]:
        print(t("  {level} - {name} {version}", level=t(component["level"]), name=component["name"], version=component["version"]))


def print_report_link(url):
    print()
    print(t('Full report (opens in a browser, kept for 7 days):'))
    print(t("{value}", value=url), flush=True)


def note(message):
    sys.stdout.flush()
    print(t("patchfirst: {message}", message=message), file=sys.stderr, flush=True)


class Progress:
    """Human check steps on an interactive stderr; JSON previews and redirected runs stay quiet."""

    def __init__(self, enabled):
        self.enabled = enabled
        self.started = self.shown = time.monotonic()

    def step(self, message):
        if self.enabled:
            note(message)
            self.shown = time.monotonic()

    def waiting(self, queue):
        now = time.monotonic()
        if not self.enabled or now - self.shown < PROGRESS_INTERVAL:
            return
        position, eta = queue_place(queue)
        if position:
            self.step(t('Waiting for the analysis... (queue position {position}, ~{minutes} min)',
                        position=position, minutes=max(1, -(-eta // 60))))
        else:
            self.step(t('Analysis in progress... {seconds} s', seconds=int(now - self.started)))


def queue_place(queue):
    if not isinstance(queue, dict):
        return 0, 0
    position, eta = queue.get('position'), queue.get('eta_seconds')
    if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in (position, eta)):
        return 0, 0
    return position, eta


def check_source(args):
    """An explicit regional URL takes precedence over the optional installed config."""
    config = {}
    config_path = getattr(args, 'config', None)
    if not args.api and config_path and os.path.isfile(config_path):
        with open(config_path) as source:
            config = json.load(source)
        if not isinstance(config, dict):
            raise uplink.ApiError('config must be an object')
    return args.api or config.get('api'), args.ca or config.get('ca')


def check(args):
    offline = getattr(args, 'offline', False)
    api, args.ca = check_source(args)
    target = getattr(args, "ssh", None)
    options = getattr(args, "ssh_opt", ())
    progress = Progress(not args.json and sys.stderr.isatty())
    progress.step(t('Collecting program versions...'))
    host = target.rsplit('@', 1)[-1] if target else socket.gethostname()
    inv = gather({'host': host}, target, options) if target else gather({'host': host})
    configure_public_scopes(api or public_package_names.DEFAULT_API, args.ca, offline=offline,
                            fallback=not bool(api), needed=public_package_names.needed_ecosystems([inv]))
    args.api = api
    # The common package list already admits public scoped names; a JSON preview makes only that GET.
    body = check_payload(target, options, inventory=inv)
    if args.json:
        print(json.dumps(body, ensure_ascii=False, indent=1))
        return 0
    progress.step(t('Sending pseudonymized data...'))
    reply = check_call(args.api, "POST", "/v1/check", body, cafile=args.ca)
    try:
        report_id, key = reply["id"], reply["key"]
        if not isinstance(report_id, str) or not isinstance(key, str):
            raise ValueError()
    except (KeyError, ValueError):
        raise uplink.ApiError("check service returned an invalid response")
    args.report_url = "%s/check/#%s.%s" % (args.api.rstrip("/"), report_id, key)
    progress.step(t('Waiting for the analysis...'))
    done = False
    try:
        wait_for_report(args, report_id, key, progress)
        done = True
        return 0
    finally:
        print_report_link(args.report_url)
        if done:
            print(file=sys.stderr)
            note(t('Paid monitoring keeps watching this server: vulnerability IDs, the versions that fix them, '
                   'and alerts when new ones appear.'))


def wait_for_report(args, report_id, key, progress):
    deadline = time.monotonic() + CHECK_TIMEOUT
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
            return
        if status == "error":
            raise uplink.ApiError("analysis failed; try the check again later")
        if status != "pending":
            raise uplink.ApiError("check service returned an invalid status")
        progress.waiting(reply.get("queue"))
        time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))


def check_help(args):
    """Failures before a report exists end with the next step, not only the reason."""
    if args.cmd == 'check' and not args.json and args.api and not getattr(args, 'report_url', None):
        note(t('Try again in a few minutes; instructions and other ways to check: {url}',
               url=args.api.rstrip('/') + '/check/'))


def prepare_payload(config, cfg, inv):
    payload, projects, _ = project_registry.prepare(config, cfg, inv,
                                                   load=load_projects, save=save_projects)
    return payload, projects


def configure_language():
    # Explicit language selection also reaches installation subprocesses.
    agent_messages.configure()
    argparse._ = t
    selector = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    selector.add_argument('--lang')
    selected, _ = selector.parse_known_args()
    try:
        agent_messages.configure(selected.lang)
    except ValueError as error:
        agent_messages.configure('en')
        selector.error(str(error))
    if selected.lang is not None:
        os.environ['PATCHFIRST_LANG'] = selected.lang
    return selected.lang


def main():
    selected_language = configure_language()
    if sys.argv[1:2] == ["migration-run"]:
        sys.argv = [sys.argv[0]] + sys.argv[4:]
    if sys.argv[1:2] == ["install-commit"]:
        from install_config import commit
        return commit(sys.argv[2:])
    if sys.argv[1:2] == ["install-config"]:
        from install_config import prepare
        return prepare(sys.argv[2:])
    ap = argparse.ArgumentParser(prog="patchfirst", description=t("Collect a server inventory, pseudonymize it locally, and send it to PatchFirst."), formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=t("patchfirst {version}", version=uplink.VERSION),
                    help=t("show program's version number and exit"))
    ap.add_argument("--lang", default=selected_language, metavar="LANG", help=t("display language (en, ru, de, fr, es)"))
    ap.add_argument("cmd", choices=("run", "dry-run", "check", "where", "id", "uninstall"))
    ap.add_argument("project", nargs="?", help=t("project number for the local where command; omit to list projects"))
    if os.geteuid() == 0:
        config_paths = (DEFAULT_CONFIG, '/etc/psr-agent.json')
    else:
        config_paths = (os.path.expanduser('~/.local/share/patchfirst/patchfirst.json'),
                        os.path.expanduser('~/.local/share/psr/psr-agent.json'))
    default_config = next((path for path in config_paths if os.path.isfile(path)), config_paths[0])
    ap.add_argument("--config", default=default_config)
    ap.add_argument("--purge", action="store_true", help=t("also remove local project numbers on uninstall"))
    ap.add_argument("--api", help=t("free check service URL"))
    ap.add_argument('--offline', action='store_true', help=t('check without network or a public package-name list'))
    ap.add_argument("--json", action="store_true", help=t("show pseudonymized JSON without sending"))
    ap.add_argument("--ca", help=t("trusted CA certificate"))
    ap.add_argument("--ssh", metavar="USER@HOST", help=t("collect over system SSH; only sh is required on the server"))
    ap.add_argument("--ssh-opt", action="append", default=[], metavar="OPTION=VALUE",
                    help=t("ssh -o setting, e.g. Port=2222 or IdentityFile=/path/key (repeatable)"))
    args = ap.parse_args()
    if args.offline and (args.cmd != 'check' or not args.json):
        ap.error(t('--offline requires check --json'))
    if args.purge and args.cmd != 'uninstall':
        ap.error(t('--purge is only used with uninstall'))
    if args.ssh_opt and not args.ssh:
        ap.error(t("--ssh-opt requires --ssh"))
    if args.ssh:
        try:
            collect.ssh_args(args.ssh, args.ssh_opt)
        except ValueError as e:
            ap.error(t(str(e)))
    if args.project and args.cmd != 'where':
        ap.error(t('project number is only used with where'))
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
                print(t('{number}\t{path}', number=number, path=path))
            return 0
        if args.cmd == "check":
            args.api, args.ca = check_source(args)
            if not (args.api or args.json):
                ap.error(t("check requires --api or --json"))
            return check(args)
        if args.cmd == "id":
            from install_config import runtime_config
            with runtime_config(args.config) as active_config, open(active_config) as f:
                print(t("{value}", value=json.load(f)["host_uuid"]))
            return 0
        from install_config import runtime_config, reject_legacy_schedule
        with runtime_config(args.config) as active_config:
            if args.cmd == 'run':
                reject_legacy_schedule(active_config)
            with open(active_config) as f:
                cfg = json.load(f)
            inv = gather(cfg, args.ssh, args.ssh_opt) if args.ssh else gather(cfg)
            configure_public_scopes(cfg.get('api') or public_package_names.DEFAULT_API, cfg.get('ca'),
                                    str(active_config) + '.public-names.gz',
                                    needed=public_package_names.needed_ecosystems([inv]))
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
            print(t("patchfirst: {message}", message=t("server quota exhausted or payment required; open the dashboard")), file=sys.stderr)
            return 2
        if isinstance(e, (uplink.ApiError, anonymize.Leak)):
            message = t(str(e))
        elif isinstance(e, OSError):
            message = t('Local operation failed: {detail}', detail=str(e))
        else:
            message = t('Invalid configuration or response: {detail}', detail=str(e))
        note(message)
        check_help(args)
        return 1
    except Exception as e:
        if args.cmd != 'check':
            raise
        note(t('Unexpected error: {name}', name=type(e).__name__))
        check_help(args)
        return 1
    c = summary["counts"]
    print(t("patchfirst: {message}", message=cfg['host'] + ' - ' + rating_text(summary)))
    print('P0 %d - P1 %d - P2 %d' % (c['P0'], c['P1'], c['P2']))
    return 0


if __name__ == "__main__":
    sys.exit(main())
