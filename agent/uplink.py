"""Service communication: anonymize the inventory, upload it, and attach the encrypted host name dictionary.
Stdlib plus optional cryptography only."""
import json
import urllib.error

import anonymize
from net import UA, http

VERSION = "1.1.1"
USER_AGENT = "%s patchfirst/%s" % (UA, VERSION)


class ApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def request(url, data=None, headers=None, **options):
    """Every agent request names the agent version."""
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
            raise ApiError("API %s %s → %d: %s" % (method, path.split("?")[0], e.code, e.read().decode()[:300]), e.code)
        except urllib.error.URLError as e:
            raise ApiError("API %s is unavailable: %s" % (self.url, e.reason))
        return json.loads(raw) if raw else None

    def fleet_path(self, tail=""):
        return "/v1/fleets/%s%s" % (self.fleet, tail)


def upload(link, host_uuid, inv, secret, words, *, projects=None, payload=None):
    """→ anonymized summary. The server name never leaves: the service knows the server only by its UUID."""
    if payload is None:
        an = anonymize.Anonymizer(secret, words, projects=projects)
        payload = an.payload(inv)
    return link.call("PUT", link.fleet_path("/hosts/%s" % host_uuid), payload)
