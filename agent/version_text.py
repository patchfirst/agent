"""The upstream release number inside a version string or an image tag."""
import re

RELEASE = re.compile(r"\d+(?:\.\d+)+(?:[a-z]+\d*)?|\d+", re.I)


def extract(text):
    value = re.sub(r'^\d+:', '', text or "")
    value = re.sub(r'(?<=\d)_[pP](?=\d)', 'p', value)
    m = RELEASE.search(value)
    return m.group(0) if m else ""
