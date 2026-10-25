"""The product catalogue: recognize a product by its image, repository or registry name."""
import ipaddress
import json
import pkgutil
import re

import version_text

DATA = json.loads(pkgutil.get_data(__name__, "products.json"))
CATALOG = DATA["products"]
for p in CATALOG:
    p["_images"] = [re.compile(rx) for rx in p.get("images", [])]


def split_image(image):
    ref = image.split("@")[0]
    name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
    return name, tag


def image_registry(image):
    name, _ = split_image(image)
    first, sep, _ = name.partition("/")
    return first if sep and ("." in first or ":" in first or first == "localhost" or
                             re.fullmatch(r"reg-[0-9a-f]{10}", first)) else "docker.io"


def image_names(name):
    """Try the existing name first, then remove only an explicit registry.

    Never drop arbitrary namespace segments: acme/node is not Node.js.
    """
    yield name
    first, sep, rest = name.partition("/")
    if sep and image_registry(name) == first:
        yield rest


def public_registry(registry):
    host = registry.lower().split(':', 1)[0]
    return host in DATA['public_image_registries'] or host.endswith('.gcr.io')


def own_image(image):
    """Require explicit private provenance; unfamiliar internet registries are unknown.

    Reserved example domains are synthetic private fixtures. Cloud tenant
    registries and local addresses identify private infrastructure; merely
    looking like a registry hostname does not establish ownership.
    """
    if re.fullmatch(r"ownimg-[0-9a-f]{10}", image):
        return True
    if by_image(image)[0]:
        return False
    registry = image_registry(image)
    if public_registry(registry):
        return False
    host = registry.lower().split(':', 1)[0]
    try:
        private_address = ipaddress.ip_address(host).is_private
    except ValueError:
        private_address = False
    return (private_address or host == 'localhost' or
            host.endswith(('.internal', '.local', '.lan', '.azurecr.io')) or
            host in DATA['private_image_registries'] or
            bool(re.fullmatch(r'\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com', host)))


def by_image(image):
    name, tag = split_image(image)
    for candidate in image_names(name):
        for p in CATALOG:
            if any(rx.search(candidate) for rx in p["_images"]):
                return p, version_text.extract(tag), tag
    return None, "", tag


def catalogue_names(name):
    """Repository suffixes the catalogue matches entirely, shortest first: no arbitrary prefix segments."""
    segments = name.split("/")
    for k in range(1, len(segments) + 1):
        candidate = "/".join(segments[-k:])
        if any(rx.fullmatch(candidate) for p in CATALOG for rx in p["_images"]):
            yield candidate


def catalogue_image(image, prefix=""):
    """The whole catalogue repository name plus the tag; '' if the catalogue does not know it.

    A private registry label prefix must still be recognized together with the name.
    """
    name, tag = split_image(image)
    candidates = list(catalogue_names(name))
    # Keep repository identities already accepted with the registry label.
    # Newly supported official mirrors fall back to their bare catalogue name.
    candidate = next((c for c in candidates if not prefix or any(
        rx.search(prefix + c) for p in CATALOG for rx in p["_images"])), "")
    if not candidate:
        candidate = next((c for c in candidates if c in image_names(name) and by_image(prefix + c)[0]), "")
    return prefix + candidate + (":" + tag if tag else "") if candidate else ""
