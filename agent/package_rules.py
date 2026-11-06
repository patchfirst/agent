"""Release and kernel selection shared by the collector and the package matcher."""
import re

KERNEL_SOURCE = re.compile(r"^linux(-signed|-meta|-restricted-modules)?"
                           r"(-(hwe|lowlatency|aws|azure|gcp|gke|oem|kvm|oracle|ibm|raspi|nvidia|lts)[a-z0-9.-]*)?$")
KERNEL_IMAGE = re.compile(r"^linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+)")
RPM_STREAM_OS = {"rocky", "almalinux", "rhel"}
SUSE_OS = {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled"}


def ecosystems(os_info):
    oid, ver = os_info.get("variant") or os_info.get("id", ""), os_info.get("version_id", "")
    if oid == "ubuntu" and ver:
        lts = ver.endswith(".04") and int(ver.split(".")[0]) % 2 == 0
        return ["Ubuntu:%s:LTS" % ver, "Ubuntu:Pro:%s:LTS" % ver] if lts else ["Ubuntu:%s" % ver]
    if oid == "debian" and ver:
        return ["Debian:%s" % ver.split(".")[0]]
    if oid == "alpine" and ver:
        return ["Alpine:v%s" % ".".join(ver.split(".")[:2])]
    if oid in ("rocky", "almalinux") and ver:
        return ["%s:%s" % ({"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[oid], ver.split(".")[0])]
    if oid == "rhel" and ver:
        return ["Red Hat:enterprise_linux:%s::%s" % (ver.split(".")[0], repo) for repo in ("baseos", "appstream")]
    if oid in ("opensuse-leap", "opensuse") and ver:
        return ["openSUSE:Leap %s" % ver]
    if oid == "opensuse-tumbleweed":
        return ["openSUSE:Tumbleweed"]
    if oid in ("sles", "sled") and re.fullmatch(r"15\.\d+", ver):
        release = "15 SP%s" % ver.split(".")[1]
        product = "Server" if oid == "sles" else "Desktop"
        return ["SUSE:Linux Enterprise %s %s" % (product, release),
                "SUSE:Linux Enterprise Module for Basesystem %s" % release]
    return []


def is_kernel(name, ecosystem=''):
    """Kernel source/binary names in distro namespaces, excluding support tools."""
    # Most inventory packages cannot be kernels in any supported namespace.
    if not name.startswith(('linux', 'kernel')):
        return False
    distro = ecosystem.split(':')[0]
    if distro == 'Alpine':
        return bool(re.fullmatch(r'linux(?:-(?:lts|edge|virt|vanilla|rpi))?', name))
    if distro in ('Rocky Linux', 'AlmaLinux', 'Red Hat', 'openSUSE', 'SUSE'):
        return bool(re.fullmatch(r'kernel(?:-(?:core|default|desktop|server|rt|uek|pae|xen))?', name))
    return bool(KERNEL_SOURCE.fullmatch(name)) and distro in ('', 'Debian', 'Ubuntu')


def kernel_source(name):
    return re.sub(r"-signed", "", name)


def relevant_os_package(inv, package):
    """Only the running kernel image represents kernel risk; omit support files."""
    kernel = inv.get("kernel", "")
    oid = inv.get("os", {}).get("id")
    if 'running_kernel' in package:
        return package['running_kernel']
    if oid in RPM_STREAM_OS | SUSE_OS and package["name"].startswith("kernel"):
        if re.search(r"-(?:modules|headers|devel|tools|doc|abi|syms)(?:-|$)", package["name"]):
            return False
        version = package["version"].split(":", 1)[-1]
        return bool(kernel) and (kernel == version or kernel.startswith((version + ".", version + "-")))
    if is_kernel(package.get("source", "")):
        return package["name"] in ("linux-image-" + kernel, "linux-image-unsigned-" + kernel)
    return True


def binary_key(name):
    """Kernel ABI numbers change with each fix; role and flavour remain the same."""
    name = name.split(':')[0]
    name = re.sub(r'^linux-image-unsigned-', 'linux-image-', name)
    return re.sub(r'^(linux-[a-z][a-z0-9.-]*)-\d+\.\d+\.\d+-\d+(?=-[a-z]|$)', r'\1-ABI', name)


def kernel_build(name):
    """Comparable numeric build of a Debian-style kernel image, if present."""
    match = KERNEL_IMAGE.match(name)
    return tuple(map(int, re.split(r'[.-]', match[1]))) if match else None
