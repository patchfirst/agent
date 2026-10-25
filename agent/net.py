"""HTTP requests and the public address check."""
import gzip
import ipaddress
import json
import os
import ssl
import time
import urllib.error
import urllib.request

UA = "psr/1.0 (+security inventory)"


def http(url, data=None, headers=None, timeout=60, retries=3, method=None, cafile=None):
    if os.environ.get("PSR_OFFLINE") == "1":
        raise RuntimeError("Network disabled for offline report generation")
    body = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
    hdrs = {"User-Agent": UA, "Accept-Encoding": "gzip"}
    if isinstance(data, (dict, list)):
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    for attempt in range(retries):
        try:
            context = ssl.create_default_context(cafile=cafile) if cafile else None
            req = urllib.request.Request(url, body, hdrs, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
                raw = r.read()
                return gzip.decompress(raw) if r.headers.get("Content-Encoding") == "gzip" else raw
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == retries - 1:
                raise
        time.sleep(2 * (attempt + 1))


def is_public_addr(addr):
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False
