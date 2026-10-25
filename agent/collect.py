"""Run remote.sh and parse its output; check port reachability.
Shared by collection over SSH (run_ssh) and the agent on the server itself (agent.py)."""
import base64
import binascii
import ipaddress
import os
import pkgutil
import re
import socket
import subprocess
import sys

import dependency_locks
import catalog
import services
from net import is_public_addr


def remote_script():
    return pkgutil.get_data(__name__, "remote.sh")


def child_environment():
    """System commands must not load libraries from PyInstaller."""
    if not getattr(sys, "frozen", False):
        return None
    env = {key: value for key, value in os.environ.items() if not key.startswith("_PYI_")}
    original = env.get("LD_LIBRARY_PATH_ORIG")
    if original is None:
        env.pop("LD_LIBRARY_PATH", None)
    else:
        env["LD_LIBRARY_PATH"] = original
    return env


def ssh_args(target, options=()):
    """Pass -o options as separate arguments; the target cannot become an option."""
    if not re.fullmatch(r"[A-Za-z0-9._@:\[\]-]+", target) or target.startswith("-"):
        raise ValueError("invalid SSH target: expected user@host or a name from ~/.ssh/config")
    cmd = ["ssh", "-T"]
    for option in options:
        if not option or any(ord(c) < 32 for c in option):
            raise ValueError("invalid SSH option: expected a setting such as Port=2222")
        cmd.extend(["-o", option])
    cmd.extend(["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ControlMaster=no"])
    return cmd


def ssh_address(target, options=()):
    """Address from the effective SSH configuration, as used by the owner's collect command."""
    cmd = ssh_args(target, options) + ["-G", "--", target]
    try:
        reply = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                               env=child_environment())
        hostname = next((line.split(None, 1)[1] for line in reply.stdout.decode("utf-8", "replace").splitlines()
                         if line.startswith("hostname ")), target.rsplit("@", 1)[-1])
        return socket.gethostbyname(hostname)
    except (OSError, subprocess.TimeoutExpired):
        return ""


def run_ssh(target, timeout=180, options=()):
    """Run remote.sh on the server over SSH (without sudo)."""
    cmd = ssh_args(target, options) + ["--", target, "sh -s"]
    try:
        r = subprocess.run(cmd, input=remote_script(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=child_environment())
    except subprocess.TimeoutExpired:
        return {"error": "таймаут ssh %d с" % timeout}
    except OSError:
        return {"error": "could not start ssh: a system SSH client is required"}
    out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    if "@@os" not in out:
        return {"error": (err.strip().splitlines() or ["ssh: код %d" % r.returncode])[-1]}
    return parse(out)


def run_local(timeout=180):
    """Run remote.sh on this machine (agent)."""
    r = subprocess.run(["sh", "-s"], input=remote_script(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, env=child_environment())
    return parse(r.stdout.decode("utf-8", "replace"))


def sections(text):
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("@@"):
            name = line[2:].strip()
            out[name] = []
        elif name and line.strip():
            out[name].append(line)
    return out


DISTRO_MAINTAINER = re.compile(r"@(?:(?:lists|packages|tracker)\.)?(?:debian\.org|ubuntu\.com|canonical\.com)>|"
                               r"@(?:lists\.alioth\.debian\.org|alioth-lists\.debian\.net)>")


KERNEL_ABI = re.compile(r"linux-(?:image|headers|modules(?:-extra)?|tools|cloud-tools|buildinfo|objects|signatures|kbuild)"
                        r"(?:-unsigned)?-(\d.*)")


def kernel_abi(name):
    """A distro kernel package: the name ends in a kernel release a distribution builds, nothing else."""
    match = KERNEL_ABI.fullmatch(name)
    return bool(match) and services.kernel_version(match[1]) == match[1]


def tsv(lines, width):
    return [(line.split("\t") + [""] * width)[:width] for line in lines]


def os_release(lines):
    kv = dict(line.split("=", 1) for line in lines if "=" in line)
    clean = {k: v.strip().strip('"') for k, v in kv.items()}
    return {"id": clean.get("ID", ""), "version_id": clean.get("VERSION_ID", ""),
            "pretty": clean.get("PRETTY_NAME", ""), "codename": clean.get("VERSION_CODENAME", "")}


def listen_ports(lines):
    ports = {}
    for line in lines:
        addr = line.split("\t", 1)[0]
        host, _, port = addr.rpartition(":")
        host = host.strip("[]").split("%")[0]
        if not port.isdigit():
            continue
        try:
            scope = "local" if ipaddress.ip_address(host).is_loopback else "all"
        except ValueError:
            scope = "all"
        if ports.get(port) != "all":
            ports[port] = scope
    return ports


def listen_services(lines):
    listeners = {}
    for line in lines:
        _, _, program = line.partition("\t")
        for port, bind in listen_ports([line]).items():
            key = (port, program)
            if key not in listeners or bind == "all":
                listeners[key] = {"port": port, "program": program, "bind": bind}
    return [listeners[key] for key in sorted(listeners, key=lambda key: (int(key[0]), key[1]))]


def packages(sec):
    if sec.get("dpkg"):
        items = [{"name": n, "version": v, "source": s or n, "source_version": sv or v, "_maintainer": m}
                 for n, v, s, sv, m in tsv(sec["dpkg"], 5)]
        return "dpkg", items
    if sec.get("rpm"):
        oid = os_release(sec.get("os", [])).get("id")
        origins = catalog.DATA["rpm_origins"]
        native = [pattern for group in origins["distro_groups"] if oid in group["os"]
                  for pattern in group["vendors"]]
        items = []
        for n, v, srpm, vendor, label in tsv(sec["rpm"], 5):
            p = {"name": n, "version": v, "source": srpm.rsplit("-", 2)[0] if srpm not in ("", "(none)") else n, "source_version": v}
            if label and label != "(none)":
                p["modularitylabel"] = label
            vendor = vendor.strip()
            p["origin"] = "local"
            if any(re.fullmatch(pattern, vendor, re.I) for pattern in native):
                p["origin"] = "distro"
            elif any(re.fullmatch(pattern, vendor, re.I) for pattern in origins["third_party_vendors"]):
                p["origin"] = "third_party"
            items.append(p)
        return "rpm", items
    if sec.get("apk"):
        items = []
        for line in sec["apk"]:
            if "\t" in line:
                n, v, source = tsv([line], 3)[0]
                items.append({"name": n, "version": v, "source": source or n, "source_version": v})
                continue
            parts = line.rsplit("-", 2)
            if len(parts) == 3:
                items.append({"name": parts[0], "version": parts[1] + "-" + parts[2], "source": parts[0],
                              "source_version": parts[1] + "-" + parts[2]})
        return "apk", items
    return "", []


def parse(text):
    sec = sections(text)
    manager, items = packages(sec)
    origins = {name: origin for name, origin, _ in tsv(sec.get("package_origins", []), 3)}
    for p in items:
        if origins.get(p["name"]) in ("distro", "third_party", "unknown", "local"):
            p["origin"] = origins[p["name"]]
        # Superseded distro builds (an old kernel ABI) vanish from the mirror but keep the distro maintainer.
        if p.get("origin") == "local" and kernel_abi(p["name"]) and DISTRO_MAINTAINER.search(p.get("_maintainer", "")):
            p["origin"] = "unknown"
        p.pop("_maintainer", None)
    reboot = sec.get("reboot", [])
    docker = None
    if sec.get("docker"):
        docker = {
            "containers": [dict(zip(("name", "image", "image_id", "ports"), row)) for row in tsv(sec["docker"], 4)],
            "images": [dict(zip(("id", "tags", "digests", "created"), row)) for row in tsv(sec.get("images", []), 4)],
        }
    apps, composer = [], []
    rows = tsv(sec.get("apps", []) + sec.get("composer", []), 5)
    packagist = {(row[1], row[2]) for row in rows if row[0] == "composer_public"}
    for row in rows:
        if row[0] == "composer":
            composer.append({"lock": row[1], "name": row[2], "version": row[3], "dev": row[4] == "1",
                             "public": (row[1], row[2]) in packagist})
        elif row[0] != "composer_public":
            apps.append({"kind": row[0], "path": row[1], "version": row[2]})
    procpkg = {}
    for line in sec.get("procpkg", []):
        if ": " in line:
            pkg, path = line.split(": ", 1)
            procpkg[path.strip()] = pkg.split(":")[0].strip()
    files = []
    for line in sec.get("deps_files", []):
        path, sep, encoded = line.partition("\t")
        if sep:
            try:
                files.append((path, base64.b64decode(encoded, validate=True).decode("utf-8", "replace")))
            except (ValueError, binascii.Error):
                continue
    deps, deps_limited = dependency_locks.collect(files, npm_registry=sec.get('deps_registry', []))
    return {
        "deps": deps,
        "deps_scan_limited": deps_limited or "limited" in sec.get("deps_scan", []),
        "deps_scan_timeout": "timeout" in sec.get("deps_scan", []),
        "deps_scan_skipped": "skipped" in sec.get("deps_scan", []),
        "composer_scan_skipped": "skipped" in sec.get("composer_scan", []),
        "os": os_release(sec.get("os", [])),
        "kernel": (sec.get("kernel") or [""])[0],
        "reboot_required": bool(reboot),
        "reboot_packages": reboot[1:],
        "package_manager": manager,
        "packages": sorted(items, key=lambda p: p["name"]),
        "upgradable": sorted(sec.get("upgradable", [])),
        "processes": sorted({row[0]: row[1] for row in tsv(sec.get("procs", []), 2)}.items()),
        "process_packages": procpkg,
        "binaries": [dict(zip(("name", "path", "owner", "version"), row)) for row in tsv(sec.get("bins", []), 4)],
        "docker": docker,
        "apps": apps,
        "composer_scan_limited": "limited" in sec.get("composer_scan", []),
        "composer_scan_timeout": "timeout" in sec.get("composer_scan", []),
        "composer": sorted(composer, key=lambda c: (c["lock"], c["name"])),
        "listen": listen_ports(sec.get("listen", [])),
        "listeners": listen_services(sec.get("listen", [])),
        "apache_php": sorted(m[:-len(".load")] for m in sec.get("apache_mods", [])),
    }


def probe(addr, port, timeout=3):
    try:
        with socket.create_connection((addr, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def listener_info(inv):
    """Different programs on the same port remain separate services."""
    if "listeners" in inv:
        inv.pop("listen", None)
        return inv.pop("listeners")
    programs = inv.pop("listen_programs", {})
    return {port: {"bind": bind, "program": programs[port]} if programs.get(port) else {"bind": bind}
            for port, bind in inv.pop("listen", {}).items()}


def exposed_ports(addr, ports, do_probe):
    rows = []
    listeners = [dict(info, port=port) for port, info in ports.items()] if isinstance(ports, dict) else ports
    for info in sorted(listeners, key=lambda row: (int(row["port"]), row.get("program", ""), row.get("bind", ""))):
        port = info["port"]
        bind = info.get("bind", "")
        reachable = None
        if bind == "all" and is_public_addr(addr) and do_probe:
            reachable = probe(addr, port)
        public = bind == "all" and is_public_addr(addr) and reachable is not False
        rows.append({"port": port, "bind": bind, "program": info.get("program", ""),
                     "reachable": reachable, "public": public})
    return rows
