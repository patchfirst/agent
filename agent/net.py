"""HTTP requests and the public address check."""
import gzip
import ipaddress
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

UA = "psr/1.0 (+security inventory)"


def origin(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme.lower(), (parts.hostname or '').lower(), parts.port


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects keep scheme, host and port; credentials never follow to another origin."""
    def __init__(self, error=None):
        super().__init__()
        self.error = error

    def redirect_request(self, request, response, code, message, headers, new_url):
        new_url = urllib.parse.urljoin(request.full_url, new_url)
        if origin(new_url) != origin(request.full_url):
            raise self.error or urllib.error.URLError('redirect to another origin refused')
        return super().redirect_request(request, response, code, message, headers, new_url)


def same_origin_opener(cafile=None, error=None):
    context = ssl.create_default_context(cafile=cafile)
    return urllib.request.build_opener(SameOriginRedirect(error), urllib.request.HTTPSHandler(context=context))


def bounded_body(response, max_bytes):
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('response is too large')
    if response.headers.get("Content-Encoding") != "gzip":
        return raw
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    body = inflater.decompress(raw, max_bytes + 1)
    if not inflater.unconsumed_tail:
        body += inflater.flush()
    if len(body) > max_bytes or inflater.unconsumed_tail:
        raise ValueError('response is too large')
    if not inflater.eof or inflater.unused_data:
        raise ValueError('invalid gzip response')
    return body


def http(url, data=None, headers=None, timeout=60, retries=3, method=None, cafile=None, response_headers=None,
         same_origin=False, max_bytes=None):
    if os.environ.get("PSR_OFFLINE") == "1":
        raise RuntimeError("Network disabled for offline report generation")
    body = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
    hdrs = {"User-Agent": UA, "Accept-Encoding": "gzip"}
    if isinstance(data, (dict, list)):
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, body, hdrs, method=method)
            if same_origin:
                opened = same_origin_opener(cafile).open(req, timeout=timeout)
            else:
                context = ssl.create_default_context(cafile=cafile) if cafile else None
                opened = urllib.request.urlopen(req, timeout=timeout, context=context)
            with opened as r:
                if response_headers is not None:
                    response_headers.update((name.lower(), value) for name, value in r.headers.items())
                if max_bytes is not None:
                    return bounded_body(r, max_bytes)
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
