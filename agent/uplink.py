"""Service communication: anonymize the inventory, upload it, and attach the encrypted host name dictionary.
Stdlib plus optional cryptography only."""
import json
import urllib.error

import anonymize
from agent_messages import t
from net import UA, http

VERSION = "1.2.1"
USER_AGENT = "%s patchfirst/%s" % (UA, VERSION)


def printable(value):
    """Server and filesystem text reaches a root terminal without control or bidi sequences."""
    return "".join(ch if ch.isprintable() else "\\x%02x" % ord(ch) if ord(ch) < 256 else "\\u%04x" % ord(ch)
                   for ch in str(value))


class ApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(t(message))
        self.status = status


MAX_RESPONSE_BYTES = 64 * 1024 * 1024


def request(url, data=None, headers=None, **options):
    """Every agent request names the agent version, stays on its origin and is size-bounded."""
    options = dict({"same_origin": True, "max_bytes": MAX_RESPONSE_BYTES}, **options)
    return http(url, data, dict(headers or {}, **{"User-Agent": USER_AGENT}), **options)


class Link:
    def __init__(self, url, fleet, token, cafile=None):
        self.url, self.fleet, self.token, self.cafile = url.rstrip("/"), fleet, token, cafile

    def call(self, method, path, body=None):
        headers = {"Authorization": "Bearer " + self.token}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        try:
            raw = request(self.url + path, data, headers, timeout=600, retries=1, method=method, cafile=self.cafile)
        except urllib.error.HTTPError as e:
            raise ApiError(t("API {method} {path} returned {status}: {reason}", method=method, path=path.split("?")[0],
                             status=e.code, reason=printable(e.read(4096).decode("utf-8", "replace")[:300])), e.code)
        except urllib.error.URLError as e:
            raise ApiError(t("API {url} is unavailable: {reason}", url=self.url, reason=e.reason))
        return json.loads(raw) if raw else None

    def fleet_path(self, tail=""):
        return "/v1/fleets/%s%s" % (self.fleet, tail)


def upload(link, host_uuid, inv, secret, words, *, projects=None, payload=None):
    """Return the pseudonymized summary. The server name never leaves: the service knows the server only by its UUID."""
    if payload is None:
        an = anonymize.Anonymizer(secret, words, projects=projects)
        payload = an.payload(inv)
    return link.call("PUT", link.fleet_path("/hosts/%s" % host_uuid), payload)
