"""Inventory to pseudonymized JSON for the API. Runs on the client; the server cannot identify the machine owner.

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
import catalog
import public_package_names
import services
import package_rules
from agent_messages import t
from net import is_public_addr

ALLOWED_TAGS = {"prod", "stage", "dev", "qa"}
FORBIDDEN_PATHS = ("/home/", "/var/www/", "/srv/", "/opt/", "/root/", "/data/", "/app/", "/www/",
                   "/usr/share/nginx/", "/usr/local/www/")


class Leak(ValueError):
    def __init__(self, message):
        super().__init__(t(message))


_ACTIVE_NAMES = object()


class Anonymizer:
    def __init__(self, secret, identity_words=(), *, projects=None, safe_displays=True, public_names=_ACTIVE_NAMES):
        if public_names is _ACTIVE_NAMES:
            self.public_names = public_package_names.current()
        else:
            self.public_names = None if public_names is None else {
                eco: frozenset(public_package_names.canonical(eco, name) for name in names)
                for eco, names in public_names.items()}
        self.os_ecosystems = []
        self.os_id = ''
        self.secret = secret.encode()
        self.words = [w.lower() for w in identity_words if w]
        self.labels = {}
        self.projects = projects if projects is not None else {}
        self.hidden_labels = set()
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
        tag = catalog.split_image(normalized)[1]
        # A tag with owner words or stray numbers (a port) is not a vendor tag: the whole image becomes a label.
        if tag and services.public_version(tag) != tag:
            return self.label("img", image)
        return normalized if services.image_reference(normalized) else self.label("img", image)

    def listed(self, name, ecosystems):
        return self.public_names is not None and any(
            public_package_names.canonical(eco, name) in self.public_names.get(eco, ()) for eco in ecosystems)

    def public_source(self, source):
        normalized = package_rules.kernel_source(source)
        if any(package_rules.is_kernel(source, eco) for eco in self.os_ecosystems) and self.listed(normalized, self.os_ecosystems):
            return normalized
        return source

    def package_permissions(self, package):
        name, source = package['name'], package['source']
        strict_catalogue = bool(catalog.by_package(name) or (catalog.by_package(source) and catalog.known_words(name)))
        return (self.listed(name, self.os_ecosystems) or strict_catalogue,
                self.listed(self.public_source(source), self.os_ecosystems) or bool(strict_catalogue and catalog.by_package(source)))

    def package(self, p):
        named, sourced = self.package_permissions(p)
        named = named and not self.marked(p['name'])
        sourced = sourced and not self.marked(p['source'])
        out = {'name': p['name'] if named else self.label('pkg', p['name']),
               'version': services.public_version(p['version']) if named else '',
               'source': self.public_source(p['source']) if sourced else self.label('pkg', p['source']),
               'source_version': services.public_version(p['source_version']) if sourced else ''}
        query_name = p['name'] if self.os_id in {'rocky', 'almalinux', 'rhel'} else self.public_source(p['source'])
        if p.get('origin') == 'distro' and self.public_names is not None and self.os_ecosystems and not self.listed(query_name, self.os_ecosystems):
            out['clean'] = True
        if p.get('origin') in ('distro', 'third_party', 'unknown', 'local'):
            out['origin'] = 'unknown' if p['origin'] == 'local' else p['origin']
        for visible, hidden, permitted in (('version', p['source'], sourced),
                                            ('source_version', p['name'], named)):
            if not permitted and hidden.lower() in out[visible].lower():
                out[visible] = services.public_version(out[visible])
                if hidden.lower() in out[visible].lower():
                    out[visible] = ''
        label = p.get('modularitylabel', '')
        if named and p.get('origin') == 'distro' and label and label != '(none)':
            parts = label.split(':')
            if len(parts) == 4 and re.fullmatch(r'\d+(?:\.\d+)*', parts[1]):
                module = parts[0]
                public = (self.listed(module, self.os_ecosystems) or catalog.by_package(module)) and not self.marked(module)
                module = module if public else self.label('pkg', module)
                out['modularitylabel'] = '%s:%s:0:0' % (module, parts[1])
            else:
                out['modularitylabel'] = 'unknown:unknown:0:0'
        return out

    def package_context(self, package, sent, inv):
        if not services.is_label(sent['name'], 'pkg'):
            return
        name = package['name']
        scope = package_rules.binary_key(name).lower()
        if self.listed(scope, self.os_ecosystems) and not self.marked(scope):
            sent['binary_scope'] = scope
        sent.update(running_kernel=self.relevant_package(package, inv), library=name.startswith('lib'))
        enabled = inv.get('apache_php')
        sent['web_module'] = name.startswith('libapache2-mod-php') and (
            enabled is None or name[len('libapache2-mod-'):] in enabled)

    def relevant_package(self, package, inv):
        return package_rules.relevant_os_package(inv, package)

    def kernel_update_available(self, inv):
        running = package_rules.kernel_build('linux-image-' + inv.get('kernel', ''))
        return running is not None and any(
            build > running for package in inv.get('packages', [])
            for build in [package_rules.kernel_build(package['name'])] if build is not None)

    def location(self, prefix, value, kind):
        label = self.label(prefix, value)
        self.display_kinds[label] = kind
        return label

    def displays(self):
        result = []
        for label, path in self.labels.items():
            if not (services.is_label(label, 'path') or services.is_label(label, 'lock')) or label in self.hidden_labels:
                continue
            folder = posixpath.dirname(path) or path
            if folder not in self.projects:
                self.projects[folder] = str(max([int(n) for n in self.projects.values()] or [0]) + 1)
            name = posixpath.basename(path)
            kind = self.display_kinds.get(label, 'program' if services.is_label(label, 'path') else 'file')
            result.append({'label': label, 'name': name if name in services.SAFE_DISPLAY_NAMES and not self.marked(name) else '',
                           'kind': kind, 'project': self.projects[folder]})
        return result

    def dependency_label(self, ecosystem, name, version):
        normalized = public_package_names.canonical(ecosystem, name)
        version = version.lstrip('v') if ecosystem == 'Packagist' else version
        label = self.label('pkg', '\0'.join((ecosystem, normalized, version)))
        self.labels[label] = name
        return label

    def dependency(self, package):
        name, eco = package['name'], package['eco']
        pattern = dependency_locks.NPM_NAME if eco == 'npm' else dependency_locks.PYPI_NAME
        valid = bool(pattern.fullmatch(name)) and not self.marked(name)
        # Listed identities are already public, even when this installed copy
        # comes from a private source. Source proof governs clean counts only.
        named = valid and self.listed(name, [eco])
        out = {'eco': eco, 'lock': self.location('lock', package['lock'], 'npm' if eco == 'npm' else 'python'),
               'name': name if named else self.dependency_label(eco, name, package['version']),
               'version': services.public_version(package['version']) if named else ''}
        if valid and not package.get('private') and package.get('public') is True and self.public_names is not None and not named:
            out['clean'] = True
        if 'dev' in package:
            out['dev'] = bool(package['dev'])
        return out

    def unlisted(self, package):
        """The catalogue exception keeps the strict whole-name rule for plugins and extras."""
        return not any(self.package_permissions(package))

    def composer(self, c):
        valid = not self.marked(c['name']) and re.fullmatch(r'[a-z0-9_.-]+/[a-z0-9_.-]+', c['name'], re.I)
        named = valid and self.listed(c['name'], ['Packagist'])
        out = {'lock': self.location('lock', c['lock'], 'composer'),
               'name': c['name'].lower() if named else self.dependency_label('Packagist', c['name'], c['version']),
               'version': services.public_version(c['version']) if named else '', 'dev': bool(c.get('dev'))}
        if valid and c.get('public') is True and self.public_names is not None and not named:
            out['clean'] = True
        return out

    def host(self, inv):
        if self.marked(inv.get("os", {}).get("pretty", "")):
            raise Leak("OS description still contains an owner identity word; refusing to send")
        self.os_ecosystems = package_rules.ecosystems(services.os_metadata(inv.get('os', {})))
        self.os_id = inv.get('os', {}).get('id', '')
        packages = [p for p in inv.get("packages", []) if not self.unlisted(p)]
        dropped = {(p['name'], p['version']): p for p in inv.get('packages', [])
                   if self.unlisted(p) and self.relevant_package(p, inv)}
        clean = sum(p.get('origin') == 'distro' for p in dropped.values()) if self.public_names is not None and self.os_ecosystems else 0
        sent_packages = [self.package(p) for p in packages]
        for original, sent in zip(packages, sent_packages):
            self.package_context(original, sent, inv)
        renamed = {p["name"]: sent["name"] for p, sent in zip(packages, sent_packages)}
        names = set(renamed)
        listeners = services.records(inv, normalize_program=self.program)
        programs = {p.get("program", "") for p in inv.get("services", inv.get("ports", [])) if isinstance(p, dict)}
        raw = {path: pkg for path, pkg in inv.get("process_packages", {}).items()
               if pkg in names and services.valid_package(pkg) and not self.marked(pkg)}
        sent = {path: self.label("path", path) for path in raw}
        self.hidden_labels.update(sent.values())
        out = {
            "kind": "host",
            "os": services.os_metadata(inv.get("os", {})),
            "kernel": services.kernel_version(inv.get("kernel", "")),
            "reboot_required": bool(inv.get("reboot_required")),
            "reboot_packages": [renamed[p] for p in inv.get("reboot_packages", []) if p in names and not self.marked(p)],
            "package_manager": inv.get("package_manager", ""),
            "packages": sent_packages,
            "unlisted_packages": len(dropped) - clean,
            "clean_packages": clean,
            "kernel_update_available": self.kernel_update_available(inv),
            "public_addr": is_public_addr(inv.get("addr", "")),
            "tags": [t for t in inv.get("tags", []) if t in ALLOWED_TAGS],
            "services": listeners,
            "process_packages": {sent[path]: renamed[pkg] for path, pkg in raw.items()},
            "processes": [[self.program(comm), sent.get(exe, "")]
                          for comm, exe in inv.get("processes", []) if comm in programs or exe in raw],
            "binaries": [{"name": self.program(b["name"]), "path": self.label("path", b["path"]),
                          "owner": renamed.get(b.get("owner", "-"), "-" if b.get("owner", "-") == "-" else self.label("pkg", b["owner"])),
                          "version": services.binary_version(b.get("version", "")) if b.get('owner', '-') == '-' or (
                              b.get('owner') in renamed and not services.is_label(renamed[b['owner']], 'pkg')) else ''}
                         for b in inv.get("binaries", [])],
            "containers_health": [{"image": self.image(c["image"])} for c in inv.get("containers_health", [])],
            "docker": {"containers": [{"image": self.image(c["image"])}
                                      for c in inv["docker"].get("containers", [])]} if inv.get("docker") else None,
            "apps": [{"kind": a["kind"] if a["kind"] in services.APP_NAMES else self.label("path", a["kind"]), "path": self.label("path", a["path"]), "version": services.public_version(a.get("version", ""))}
                     for a in inv.get("apps", [])],
            "composer": [self.composer(c) for c in inv.get("composer", [])],
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
            out["error"] = services.error_marker(inv["error"])
        return out

    def inventory(self, inv):
        return self.host(inv)

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
                    if "*" in schema and not (services.is_label(key, "path") and services.owned_key(key, item)):
                        raise Leak("process path is not a label; refusing to send")
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
            elif schema is int:
                if type(value) is not int or not 0 <= value <= services.MAX_COUNT:
                    raise Leak("invalid anonymized JSON count")
            elif schema is str and not services.valid_leaf(path, value, owned):
                raise Leak("invalid anonymized JSON value; refusing to send")

        check(data, services.INVENTORY_SCHEMA)
        text = json.dumps(data, ensure_ascii=False)
        low = text.lower()
        secrets = [s for s in (inv.get("addr"), inv.get("ssh")) if s and re.search(r"[@.]", s)]
        found = [s for s in secrets if s in text] + [p for p in FORBIDDEN_PATHS if p in text]
        found += [w for w in self.words if w in low]
        if found:
            raise Leak(t("anonymized JSON still contains: {values}; refusing to send", values=", ".join(sorted(set(found)))))
