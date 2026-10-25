"""Inventory → anonymized JSON for the API. Runs on the client; the server cannot identify the machine owner.

Send only what vulnerability matching needs: OS, packages, versions, and public exposure flags.
Port numbers are not sent. Replace addresses, names, paths, private images, and namespace/workload names with labels
HMAC(local secret, value): the server cannot recover them by brute force.
The label dictionary stays in the anonymization process; only a safe display label is sent to the service.
Final check before sending: JSON must contain no addresses, paths, or the owner's identity words.
"""
import hashlib
import hmac
import json
import posixpath
import re

import dependency_locks
import npm_scopes
import catalog
import services
from net import is_public_addr

ALLOWED_TAGS = {"prod", "stage", "dev", "qa"}
FORBIDDEN_PATHS = ("/home/", "/var/www/", "/srv/", "/opt/", "/root/", "/data/", "/app/", "/www/",
                   "/usr/share/nginx/", "/usr/local/www/")


class Leak(ValueError):
    pass


class Anonymizer:
    def __init__(self, secret, identity_words=(), *, projects=None, safe_displays=True):
        self.secret = secret.encode()
        self.words = [w.lower() for w in identity_words if w]
        self.labels = {}
        self.projects = projects if projects is not None else {}
        self.safe_displays = safe_displays
        self.display_kinds = {}

    def label(self, prefix, value):
        tag = hmac.new(self.secret, ("%s:%s" % (prefix, value)).encode(), hashlib.sha256).hexdigest()[:10]
        name = "%s-%s" % (prefix, tag)
        self.labels[name] = value
        return name

    def marked(self, text):
        low = (text or "").lower()
        return any(w in low for w in self.words)

    def program(self, name):
        if not name:
            return ""
        known = services.program_name(name)
        return known if known and not self.marked(name) else self.label("path", name)

    def image(self, image):
        """Catalog portion and tag; an unknown image from a private registry gets its own label."""
        if catalog.own_image(image):
            return self.label("ownimg", image)
        if not catalog.by_image(image)[0] or self.marked(image):
            return self.label("img", image)
        name = image.split("@")[0]
        first = name.split("/")[0]
        registry = first if "/" in name and ("." in first or ":" in first) else "docker.io"
        prefix = "" if catalog.public_registry(registry) else self.label("reg", registry) + "/"
        normalized = catalog.catalogue_image(name, prefix)
        return normalized if services.image_reference(normalized) else self.label("img", image)

    def package(self, p):
        out = {k: p[k] for k in ("name", "version", "source", "source_version")}
        if p.get("origin") in ("distro", "third_party", "unknown"):
            out["origin"] = p["origin"]
        label = p.get("modularitylabel", "")
        if re.fullmatch(r"[a-zA-Z0-9_.+-]+(?::[a-zA-Z0-9_.+-]+){3}", label) and not self.marked(label):
            out["modularitylabel"] = label
        if self.marked(p["name"]) or self.marked(p["source"]):
            out.update(name=self.label("pkg", p["name"]), source=self.label("pkg", p["source"]))
        return out

    def location(self, prefix, value, kind):
        label = self.label(prefix, value)
        self.display_kinds[label] = kind
        return label

    def displays(self):
        result = []
        for label, path in self.labels.items():
            if not (services.is_label(label, 'path') or services.is_label(label, 'lock')):
                continue
            folder = posixpath.dirname(path) or path
            if folder not in self.projects:
                self.projects[folder] = str(max([int(n) for n in self.projects.values()] or [0]) + 1)
            name = posixpath.basename(path)
            kind = self.display_kinds.get(label, 'program' if services.is_label(label, 'path') else 'file')
            result.append({'label': label, 'name': name if name in services.SAFE_DISPLAY_NAMES and not self.marked(name) else '',
                           'kind': kind, 'project': self.projects[folder]})
        return result

    def dependency(self, package):
        name = package["name"]
        pattern = dependency_locks.NPM_NAME if package["eco"] == "npm" else dependency_locks.PYPI_NAME
        private = package.get('private', False) or not pattern.fullmatch(name) or self.marked(name) or (
            package["eco"] == "npm" and name.startswith("@") and
            name.split("/", 1)[0] not in self.public_scopes())
        out = {"eco": package["eco"], "lock": self.location("lock", package["lock"], "npm" if package["eco"] == "npm" else "python"),
               "name": self.label("pkg", name) if private else name, "version": package["version"]}
        if "dev" in package:
            out["dev"] = bool(package["dev"])
        return out

    def host(self, inv):
        if self.marked(inv.get("os", {}).get("pretty", "")):
            raise Leak("OS description still contains an owner identity word; refusing to send")
        listeners = services.records(inv, normalize_program=self.program)
        programs = {p.get("program", "") for p in inv.get("services", inv.get("ports", [])) if isinstance(p, dict)}
        raw = {path: pkg for path, pkg in inv.get("process_packages", {}).items()
               if services.system_path(path) and services.valid_package(pkg) and not self.marked(path) and not self.marked(pkg)}
        sent = services.owned_paths(raw, lambda path: self.label("path", path))
        out = {
            "kind": "host",
            "os": services.os_metadata(inv.get("os", {})),
            "kernel": inv.get("kernel", ""),
            "reboot_required": bool(inv.get("reboot_required")),
            "reboot_packages": [p for p in inv.get("reboot_packages", []) if not self.marked(p)],
            "package_manager": inv.get("package_manager", ""),
            "packages": [self.package(p) for p in inv.get("packages", [])],
            "public_addr": is_public_addr(inv.get("addr", "")),
            "tags": [t for t in inv.get("tags", []) if t in ALLOWED_TAGS],
            "services": listeners,
            "process_packages": {sent[path]: pkg for path, pkg in raw.items()},
            "processes": [[self.program(comm), sent.get(exe, "")]
                          for comm, exe in inv.get("processes", []) if comm in programs or exe in raw],
            "binaries": [{"name": self.program(b["name"]), "path": self.label("path", b["path"]), "owner": b.get("owner", "-"),
                          "version": services.binary_version(b.get("version", ""))} for b in inv.get("binaries", [])],
            "containers_health": [{"image": self.image(c["image"])} for c in inv.get("containers_health", [])],
            "docker": {"containers": [{"image": self.image(c["image"])}
                                      for c in inv["docker"].get("containers", [])]} if inv.get("docker") else None,
            "apps": [{"kind": a["kind"] if a["kind"] in services.APP_NAMES else self.label("path", a["kind"]), "path": self.label("path", a["path"]), "version": a.get("version", "")}
                     for a in inv.get("apps", [])],
            "composer": [{"lock": self.location("lock", c["lock"], "composer"),
                          "name": self.label("pkg", c["name"]) if self.marked(c["name"]) or
                          not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", c["name"], re.I) else c["name"].lower(),
                          "version": c["version"], "dev": bool(c.get("dev"))} for c in inv.get("composer", [])],
            "deps": [self.dependency(p) for p in inv.get("deps", [])],
            "deps_scan_limited": bool(inv.get("deps_scan_limited")),
            "deps_scan_timeout": bool(inv.get("deps_scan_timeout")),
            "deps_scan_skipped": bool(inv.get("deps_scan_skipped")),
            "composer_scan_skipped": bool(inv.get("composer_scan_skipped")),
            "composer_scan_limited": bool(inv.get("composer_scan_limited")),
            "composer_scan_timeout": bool(inv.get("composer_scan_timeout")),
            "apache_php": inv.get("apache_php"),
        }
        if inv.get("error"):
            out["error"] = services.COLLECTION_FAILED
        return out

    def inventory(self, inv):
        return self.host(inv)

    def public_scopes(self):
        return npm_scopes.public_scopes()

    def payload(self, inv):
        data = self.inventory(inv)
        if self.safe_displays:
            data['safe_displays'] = self.displays()
        data = services.clean(data, owned=data.get("process_packages", {}))
        self.verify(data, inv)
        return data

    def verify(self, data, inv):
        owned = data.get("process_packages", {})

        def check(value, schema, path=()):
            if value is None and path in services.NULLABLE:
                return
            if isinstance(schema, dict):
                if not isinstance(value, dict):
                    raise Leak("invalid anonymized JSON structure")
                for key, item in value.items():
                    if str(key).lower() in {"port", "ports", "public_ports"}:
                        raise Leak("anonymized JSON still contains a port key; refusing to send")
                    if key not in schema and "*" not in schema:
                        raise Leak("unknown anonymized JSON field; refusing to send")
                    if "*" in schema and not services.owned_key(key, item):
                        raise Leak("unknown process path; refusing to send")
                    check(item, schema.get(key, schema.get("*")), path + ("*" if "*" in schema else key,))
            elif isinstance(schema, (list, tuple)):
                if not isinstance(value, (list, tuple)) or isinstance(schema, tuple) and len(value) != len(schema):
                    raise Leak("invalid anonymized JSON list")
                for index, item in enumerate(value):
                    check(item, schema[index] if isinstance(schema, tuple) else schema[0],
                          path + (index if isinstance(schema, tuple) else "*",))
            elif schema is bool:
                if type(value) is not bool:
                    raise Leak("invalid anonymized JSON flag")
            elif schema is str and not services.valid_leaf(path, value, owned):
                raise Leak("invalid anonymized JSON value; refusing to send")

        check(data, services.INVENTORY_SCHEMA)
        text = json.dumps(data, ensure_ascii=False)
        low = text.lower()
        secrets = [s for s in (inv.get("addr"), inv.get("ssh")) if s and re.search(r"[@.]", s)]
        found = [s for s in secrets if s in text] + [p for p in FORBIDDEN_PATHS if p in text]
        found += [w for w in self.words if w in low]
        if found:
            raise Leak("anonymized JSON still contains: %s; refusing to send" % ", ".join(sorted(set(found))))
