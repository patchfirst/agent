"""The upstream release number inside a version string or an image tag."""
import re

RELEASE = re.compile(r"\d+(?:\.\d+)+(?:[a-z]+\d*)?|\d+", re.I)


def extract(text):
    m = RELEASE.search(text or "")
    return m.group(0) if m else ""
