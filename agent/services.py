"""Listening service types: port numbers are used only locally and are not included in records."""
import json
import pkgutil
import re

import catalog
import version_text

COLLECTION_FAILED = "сбор не удался"

CATEGORIES = json.loads(pkgutil.get_data(__name__, "service_categories.json"))
_PROGRAMS = [(category, re.compile(pattern, re.I))
             for category, row in CATEGORIES.items() for pattern in row["programs"]]
_PORTS = {str(port): category for category, row in CATEGORIES.items() for port in row["ports"]}
# Program identities come from the product catalogue, never from a permissive
# executable-name grammar.
PROGRAM_NAMES = {name for product in catalog.CATALOG for field in ("binaries", "programs")
                 for name in product.get(field, [])}
APP_NAMES = {name for product in catalog.CATALOG for name in product.get("apps", [])}
_LABEL = re.compile(r"(?:path|pkg|img|ownimg|reg|ns|node|lock)-[0-9a-f]{10}")
# ASCII and case-exact (Python re is Unicode/IGNORECASE-aware).
_VERSION = re.compile(r"v?\d[0-9A-Za-z.+~!_-]*|dev-[0-9A-Za-z.-]+", re.A)
_PACKAGE_VERSION = re.compile(r"(?:\d+:)?(?:v?\d[0-9A-Za-z.+~!_-]*|dev-[0-9A-Za-z.-]+)", re.A)
_PACKAGE_NAME = re.compile(r"(?:@[\w.-]+/)?[\w][\w.+/-]*(?::(?:amd64|i[3-6]86|arm64|armhf|armel|all|noarch|ppc64el|s390x))?", re.A)
_SYSTEM_PATH = re.compile(r"/(?:usr|bin|sbin|lib|lib64)/(?:[A-Za-z0-9_+.-]+/)*[A-Za-z0-9_+.-]+")
# Upstream release only: attached letters (9.2p1, 1.1.1k), Java 8 updates
# (1.8.0_402) and pre-releases (-rc1) stay; distribution builds (-MariaDB-0+deb12u1, -1ubuntu3) would compare as older.
_VERSION_TOKEN = re.compile(r"v?\d+(?:\.\d+)+(?:_\d+)?(?:[a-z]+\d*)?(?:-(?:rc|alpha|beta|pre)\.?\d*)?")
# A bare integer is a release only right after a known --version prefix
# (openjdk 21); elsewhere it may be a listener number.
_BINARY_PREFIX = re.compile(
    r"(?:PHP(?:-FPM)?|postgres \(PostgreSQL\)|OpenSSL|Python|node(?:\.js)?|"
    r"(?:openjdk|java)(?: version)? [\"]?|(?:Docker|runc|kubelet|Kubernetes|clickhouse|memcached|certbot|git|sudo)"
    r"(?: version)?)[ \t]*v?(\d+)\b", re.I)
_DIGITS = re.compile(r"\d+")
NULLABLE = {("docker",), ("apache_php",), ("services", "*", "reachable")}


def is_label(value, prefix=None):
    return isinstance(value, str) and bool(_LABEL.fullmatch(value)) and (not prefix or value.startswith(prefix + "-"))


def valid_version(value, package=False):
    return isinstance(value, str) and (not value or bool((_PACKAGE_VERSION if package else _VERSION).fullmatch(value)))


def valid_package(value):
    return isinstance(value, str) and bool(_PACKAGE_NAME.fullmatch(value)) and bool(re.search(r"[A-Za-z]", value))


def system_path(value):
    return isinstance(value, str) and bool(_SYSTEM_PATH.fullmatch(value)) and not any(
        part in {".", ".."} for part in value.split("/"))


def owner_path(path, package):
    """A package path leaves as is only if its numbers come from the package name or are under three digits."""
    return system_path(path) and valid_package(package) and all(
        len(number) <= 2 or number in package for number in _DIGITS.findall(path))


def owned_key(key, package):
    return valid_package(package) and (is_label(key, "path") or owner_path(key, package))


def program_name(value, owned=None):
    """A catalogue identity or an existing opaque owner label; no free names."""
    if not isinstance(value, str):
        return ""
    if value in PROGRAM_NAMES or is_label(value, "path") or value == "app":
        return value
    if system_path(value):
        value = value.rsplit("/", 1)[-1]
    aliases = ((r"php(?:[5-9](?:\.\d{1,2})?)?", "php"),
               (r"php(?:-fpm[5-9](?:\.\d{1,2})?|[5-9](?:\.\d{1,2})?-fpm)", "php-fpm"),
               (r"python[23](?:\.\d{1,2})?", "python3"))
    if value in PROGRAM_NAMES:
        return value
    return next((canonical for pattern, canonical in aliases if re.fullmatch(pattern, value)), "")


_KERNEL = re.compile(r"(\d+\.\d+(?:\.\d+)?)((?:[-.+_~][0-9A-Za-z]+)*)", re.A)
# Words vendors, distributions and clouds put into versions; anything else may name the owner (1.2.3-acme).
_BUILD_WORDS = {
    "generic", "amd64", "arm64", "armhf", "armel", "i386", "i686", "x86", "aarch64", "noarch", "cloud", "rt", "aws",
    "azure", "gcp", "gke", "kvm", "lowlatency", "oracle", "ibm", "raspi", "rpi", "nvidia", "lts", "virt", "pve", "hwe",
    "oem", "edge", "microsoft", "standard", "wsl", "uek", "default", "pae", "lpae", "mainline", "fips", "arch", "deb",
    "bpo", "ubuntu", "debian", "dfsg", "build", "git", "really", "nmu", "amzn", "module", "alpine", "alpha", "beta",
    "pre", "post", "dev", "esm", "stable", "focal", "jammy", "noble", "bionic", "xenial", "bookworm", "bullseye",
    "buster", "trixie", "stretch", "slim", "fpm", "apache", "cli", "management", "community", "enterprise", "legacy",
    "final", "release", "snapshot", "nightly", "static", "musl", "glibc", "jdk", "jre", "openjdk", "temurin", "zulu",
    "corretto", "ubi", "rootless", "perl", "otel", "hotfix", "patch", "update", "pgdg", "sles", "mga", "ph", "lp",
    "ol", "el", "fc", "bin", "linux", "windows", "darwin", "go", "php", "node", "python", "mysql", "mariadb", "redis",
    "nginx", "busybox", "distroless", "nonroot", "full", "lite", "minimal", "core", "server", "client", "common",
    "rocky", "alma", "centos", "rhel", "fedora", "opensuse", "suse", "zabbix", "grafana", "docker", "ce", "ee"}
_SHORT_WORDS = {"rc", "el", "fc", "ce", "ee", "lp", "ol", "ph", "rt", "ga", "ea", "sp", "pl"}
_DOTTED_QUAD = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


def _internal_address(value):
    import ipaddress
    for quad in _DOTTED_QUAD.findall(value):
        try:
            address = ipaddress.ip_address(quad)
        except ValueError:
            continue
        if not address.is_global:
            return True
    return False


def _build_token(token):
    letters = re.sub(r"\d+", "", token)
    return (token in _BUILD_WORDS or letters in _BUILD_WORDS or len(letters) == 1 or letters in _SHORT_WORDS
            or bool(re.fullmatch(r"(?:deb|bpo|ubuntu|el|fc|amzn|ol)\d+(?:u\d+)?(?:_\d+)?", token)))


def public_version(value):
    """A version as vendors publish it; an owner word or an internal address leaves only the upstream release."""
    if not isinstance(value, str) or not value:
        return ""
    tokens = {token.lower() for token in re.split(r"[^0-9A-Za-z]+", value) if re.search(r"[A-Za-z]", token)}
    if all(_build_token(token) for token in tokens) and not _internal_address(value):
        return value
    release = re.sub(r"(\d)[A-Za-z]{2,}\d*$", r"\1", version_text.extract(re.sub(r"^\d+:", "", value)))
    return "" if _internal_address(release) else release


def kernel_version(value):
    """The kernel release as a distribution builds it; an unknown suffix leaves only the upstream version."""
    match = _KERNEL.fullmatch(value or "")
    if not match:
        return ""
    return value if public_version(value) == value else match[1]


def binary_version(value):
    """Only a parsed release token leaves the owner; raw tool output stays local.

    The first dotted release on the first line is the version (ClickHouse,
    Zabbix, MySQL print it after free words). The program's own path at the
    start of the line belongs to the owner and is skipped.
    """
    if not isinstance(value, str) or value in {"", "-"}:
        return ""
    line = value.split("\n", 1)[0].strip()
    if line.startswith("/"):
        line = line.partition(" ")[2]
    for match in _VERSION_TOKEN.finditer(line):
        if not _internal_address(match.group(0)):
            return public_version(match.group(0))
    if re.fullmatch(r"v?\d+", line):
        return line
    match = _BINARY_PREFIX.match(line)
    return match.group(1) if match else ""


def category_for(port=None, program=""):
    """A known program is more reliable than a port number, including on nonstandard ports."""
    name = str(program or "").split()[0].rsplit("/", 1)[-1] if str(program or "").strip() else ""
    for category, pattern in _PROGRAMS:
        if pattern.fullmatch(name):
            return category
    return _PORTS.get(str(port), "other")


def records(inv, normalize_program=None):
    """Safe common representation of new and legacy inventories without port numbers or arbitrary fields."""
    source = inv.get("services", inv.get("ports", []))
    if not isinstance(source, list):
        return []
    out = []
    for row in source:
        if not isinstance(row, dict):
            continue
        program = row.get("program", "")
        program = program if isinstance(program, str) else ""
        category = row.get("category")
        if not isinstance(category, str) or category not in CATEGORIES:
            category = category_for(row.get("port"), program)
        program = normalize_program(program) if normalize_program else (program_name(program) or "app" if program else "")
        out.append({"program": program, "category": category,
                    "bind": "local" if row.get("bind") == "local" else "all",
                    "public": bool(row.get("public")),
                    "reachable": row.get("reachable") if type(row.get("reachable")) is bool else None})
    return out


OS_NAMES = {"debian": "Debian GNU/Linux", "ubuntu": "Ubuntu", "alpine": "Alpine Linux",
            "fedora": "Fedora Linux", "rhel": "Red Hat Enterprise Linux", "centos": "CentOS Linux",
            "rocky": "Rocky Linux", "almalinux": "AlmaLinux", "amzn": "Amazon Linux",
            "arch": "Arch Linux", "gentoo": "Gentoo", "opensuse-leap": "openSUSE Leap",
            "opensuse-tumbleweed": "openSUSE Tumbleweed", "sles": "SUSE Linux Enterprise Server",
            "freebsd": "FreeBSD", "flatcar": "Flatcar Container Linux", "bottlerocket": "Bottlerocket OS",
            "cos": "Container-Optimized OS from Google"}
OS_CODENAMES = {"jessie", "stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "duke",
                "xenial", "bionic", "focal", "jammy", "noble", "oracular", "plucky", "questing",
                "resolute", "sid", "testing", "stable"}
_OS_PRETTY = re.compile(r"(?:" + "|".join(re.escape(name) for name in [*OS_NAMES.values(), "Debian", "Alpine"]) +
                        r")(?: GNU/Linux)?(?: \d+(?:\.\d+)*)?(?: LTS)?(?: \((?:" +
                        "|".join(OS_CODENAMES) + r")\)| (?:" + "|".join(OS_CODENAMES) + r"))?")
_FLOATING_TAGS = {"latest", "stable", "mainline", "alpine", "bookworm", "bullseye", "trixie", "slim", "lts"}


def os_pretty(value):
    return isinstance(value, str) and bool(_OS_PRETTY.fullmatch(value))


def os_metadata(value):
    """Rebuild presentation text from OS identities instead of arbitrary prose."""
    ident = value.get("id", "")
    ident = ident if ident in OS_NAMES else ""
    version = value.get("version_id", "")
    version = version if re.fullmatch(r"\d+(?:\.\d+)*", version) else ""
    codename = value.get("codename", "")
    codename = codename if codename in OS_CODENAMES else ""
    pretty = value.get("pretty", "")
    if not os_pretty(pretty):
        pretty = " ".join(part for part in (OS_NAMES[ident], version) if part) if ident else ""
        if pretty and codename:
            pretty += " (" + codename + ")"
    return {"id": ident, "version_id": version, "pretty": pretty, "codename": codename}


def normalize_image(value):
    """Only the catalogue-recognized part of an image name and its tag; owner labels stay."""
    if not isinstance(value, str) or (is_label(value, "img") or is_label(value, "ownimg")):
        return value if isinstance(value, str) else ""
    name, sep, digest = value.partition("@sha256:")
    digest = sep + digest if sep and re.fullmatch(r"[0-9a-fA-F]{64}", digest) else ""
    first, _, rest = name.partition("/")
    name = catalog.catalogue_image(rest, first + "/") if is_label(first, "reg") else catalog.catalogue_image(name)
    return name + digest if name else ""


def image_reference(value):
    """Catalogue part of the repository plus an actual version/fixed tag."""
    if (is_label(value, "img") or is_label(value, "ownimg")):
        return True
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./:@+-]+", value):
        return False
    tag = catalog.split_image(value)[1]
    if tag and not (valid_version(tag) or tag in _FLOATING_TAGS):
        return False
    return bool(value) and normalize_image(value) == value


# Safe display names are technical catalogue identities, never owner filenames.
SAFE_FILE_NAMES = {'composer.lock', 'package-lock.json', 'npm-shrinkwrap.json',
                   'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'Pipfile.lock',
                   'poetry.lock', 'uv.lock', 'pyproject.toml'}
SAFE_DISPLAY_NAMES = SAFE_FILE_NAMES | PROGRAM_NAMES | APP_NAMES
SAFE_DISPLAY_KINDS = {'composer', 'npm', 'python', 'program', 'file'}

INVENTORY_SCHEMA = {
    "safe_displays": [{key: str for key in ("label", "name", "kind", "project")}],
    "kind": str, "os": {key: str for key in ("id", "version_id", "pretty", "codename")},
    "kernel": str, "reboot_required": bool, "reboot_packages": [str], "package_manager": str,
    "packages": [{key: str for key in ("name", "version", "source", "source_version", "origin", "modularitylabel")}],
    "public_addr": bool, "tags": [str], "process_packages": {"*": str}, "processes": [(str, str)],
    "services": [{"program": str, "category": str, "bind": str, "public": bool, "reachable": bool}],
    "binaries": [{key: str for key in ("name", "path", "owner", "version")}],
    "containers_health": [{"image": str}], "docker": {"containers": [{"image": str}]},
    "apps": [{key: str for key in ("kind", "path", "version")}],
    "composer": [{**{key: str for key in ("lock", "name", "version")}, "dev": bool}],
    "deps": [{"eco": str, "lock": str, "name": str, "version": str, "dev": bool}],
    "apache_php": [str], "error": str, "unlisted_packages": int,
    "images": [{"namespace": str, "image": str, "image_id": str, "workloads": [str], "public": bool}],
    "nodes": [{key: str for key in ("name", "osImage", "kernelVersion", "kubeletVersion", "containerRuntimeVersion")}],
    **{prefix + flag: bool for prefix in ("deps_scan_", "composer_scan_")
       for flag in ("limited", "timeout", "skipped")},
}


def valid_leaf(path, value, owned=None):
    """Validate the declared meaning of a string, without searching for numbers.

    List members use '*'; process tuple positions may be 0/1. Package-owned
    system executables retain their exact paths for exposure attribution.
    """
    if not isinstance(value, str):
        return False
    if not value and path not in {('safe_displays', '*', 'label'), ('safe_displays', '*', 'kind'), ('safe_displays', '*', 'project')}:
        return True
    if path[:2] == ('safe_displays', '*'):
        if path[-1] == 'name':
            return value in SAFE_DISPLAY_NAMES
        if path[-1] == 'label':
            return is_label(value, 'path') or is_label(value, 'lock') or is_label(value, 'node')
        if path[-1] == 'kind':
            return value in SAFE_DISPLAY_KINDS or value == 'node'
        if path[-1] == 'project':
            return bool(re.fullmatch(r'[1-9][0-9]{0,5}', value))
        return False
    if path == ('packages', '*', 'origin'):
        return value in {'distro', 'third_party', 'unknown'}
    if path == ('packages', '*', 'modularitylabel'):
        return bool(re.fullmatch(r'[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+:[0-9]+:[A-Za-z0-9_]+|\(none\)', value))
    owned = owned or {}
    if path == ("services", "*", "program") or path == ("processes", "*", 0):
        return value in PROGRAM_NAMES or value == "app" or is_label(value, "path")
    if path == ("services", "*", "category"):
        return value in CATEGORIES
    if path == ("services", "*", "bind"):
        return value in {"all", "local"}
    if path == ("processes", "*", 1):
        return value in owned and owned_key(value, owned[value])
    if path == ("process_packages", "*"):
        return valid_package(value) or is_label(value, "pkg")
    if path in {("binaries", "*", "name"), ("apps", "*", "kind")}:
        return value in (PROGRAM_NAMES if path[0] == "binaries" else APP_NAMES) or is_label(value, "path")
    if path in {("binaries", "*", "path"), ("apps", "*", "path")}:
        return is_label(value, "path")
    if path in {("deps", "*", "lock"), ("composer", "*", "lock")}:
        return is_label(value, "lock")
    if path == ("binaries", "*", "owner"):
        return value == "-" or valid_package(value) or is_label(value, "pkg")
    if path[-1:] in {("version",), ("source_version",), ("version_id",), ("kernelVersion",), ("kubeletVersion",)} or path == ("kernel",):
        return valid_version(value, package=path[0] == "packages")
    if path == ("nodes", "*", "containerRuntimeVersion"):
        prefix, sep, version = value.partition("://")
        return bool(sep) and prefix in {"docker", "containerd", "cri-o"} and valid_version(version)
    if path == ("nodes", "*", "name"):
        return is_label(value, "node")
    if path == ("deps", "*", "eco"):
        return value in {"npm", "PyPI"}
    if path == ("kind",):
        return value in {"host", "k8s"}
    if path == ("package_manager",):
        return value in {"dpkg", "rpm", "apk", "apt", "deb"}
    if path == ("tags", "*"):
        return value in {"prod", "stage", "dev", "qa"}
    if path == ("apache_php", "*"):
        return bool(re.fullmatch(r"(?:php[5-9](?:\.\d{1,2})?|mpm_(?:event|prefork|worker))", value))
    if path == ("error",):
        return value == COLLECTION_FAILED
    if path == ("images", "*", "image_id") or path == ("images", "*", "workloads", "*"):
        return False
    # These fields have their own bounded domain grammars (OS/package/image
    # metadata), rather than accepting arbitrary objects or tool output.
    if path[:1] in {("packages",), ("composer",), ("deps",), ("reboot_packages",)}:
        return valid_package(value) or is_label(value, "pkg")
    if path in {("os", "id"), ("os", "codename")}:
        return value in (OS_NAMES if path[-1] == "id" else OS_CODENAMES)
    if path in {("os", "pretty"), ("nodes", "*", "osImage")}:
        return os_pretty(value)
    if path == ("images", "*", "namespace"):
        return value in {"default", "kube-system", "kube-public", "kube-node-lease", "ingress-nginx", "cert-manager",
                         "monitoring", "calico-system", "tigera-operator"} or is_label(value, "ns")
    if path[-1:] == ("image",):
        return image_reference(value)
    return False


LIMIT = 256
HEADLINE_LIMIT = 80
MAX_COUNT = 1000000


def clean(value, schema=INVENTORY_SCHEMA, path=(), owned=None, program=None):
    """Allowlist of fields and types: discard invalid values instead of failing the upload."""
    if schema is str:
        if not isinstance(value, str):
            return ""
        if path == ("processes", "*", 0):
            value = (program or program_name)(value)
        elif path == ("binaries", "*", "name"):
            value = program_name(value)
        elif path == ("binaries", "*", "version"):
            value = binary_version(value)
        elif path[-1:] == ("image",):
            value = normalize_image(value)
        elif path == ("error",) and value:
            value = COLLECTION_FAILED
        limit = HEADLINE_LIMIT if path == ("os", "pretty") else LIMIT
        return value if len(value) <= limit and valid_leaf(path, value, owned) else ""
    if value is None and path in NULLABLE:
        return None
    if schema is bool:
        return bool(value)
    if schema is int:
        return value if type(value) is int and 0 <= value <= MAX_COUNT else 0
    if isinstance(schema, list):
        return [clean(item, schema[0], path + ("*",), owned, program) for item in value] \
            if isinstance(value, list) else []
    if isinstance(schema, tuple):
        return [clean(item, field, path + (index,), owned, program)
                for index, (item, field) in enumerate(zip(value, schema))] \
            if isinstance(value, (list, tuple)) and len(value) == len(schema) else ["", ""]
    if isinstance(schema, dict):
        if not isinstance(value, dict):
            return {}
        return {k: clean(item, schema.get(k, schema.get("*")), path + ("*" if "*" in schema else k,), owned, program)
                for k, item in value.items() if k in schema and k != "*" or ("*" in schema and owned_key(k, item))}
    return None
