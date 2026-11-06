"""One common streamed public-name file; only this inventory's ecosystems stay in memory."""
from contextlib import contextmanager, ExitStack
import fcntl
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import re
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib

from agent_messages import t
from package_rules import ecosystems

DEFAULT_API = 'https://patchfirst.dev'
FALLBACK_API = 'https://ru.patchfirst.dev'
REQUEST_TIMEOUT = 6
TOTAL_TIMEOUT = 12
MAX_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 2850
_HEADER = re.compile(br'#patchfirst-public-names 2 (0|[1-9][0-9]{0,18})\n\Z')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')
_active = None


def canonical(ecosystem, name):
    return re.sub(r'[-_.]+', '-', name).lower() if ecosystem == 'PyPI' else name.lower()


def use(values):
    global _active
    # Streamed selections are already canonical sets. Do not duplicate a large
    # registry while activating it; list-valued local callers are normalized.
    _active = None if values is None else values if all(isinstance(v, (set, frozenset)) for v in values.values()) else {
        eco: frozenset(canonical(eco, name) for name in names) for eco, names in values.items()}


def current():
    return _active


def needed_ecosystems(inventories):
    from services import os_metadata
    needed = set()
    for inventory in inventories:
        needed.update(ecosystems(os_metadata(inventory.get('os', {}))))
        needed.update(dep['eco'] for dep in inventory.get('deps', []) if dep.get('eco') in {'npm', 'PyPI'})
        if inventory.get('composer'):
            needed.add('Packagist')
    return needed


def default_cache():
    return Path(os.path.expanduser('~/.local/share/patchfirst/public-names.gz'))


def read_list(path, needed=()):
    """Validate every bounded UTF-8 row, retaining only locally selected names."""
    selected, needed = {}, set(needed or ())
    total, previous, previous_eco = 0, None, None
    eco, bucket = '', None
    try:
        with gzip.open(path, 'rb') as source:
            header = source.readline(65)
            match = _HEADER.fullmatch(header)
            if not match or int(match[1]) >= 2 ** 63:
                raise ValueError('invalid public package-name list')
            revision, total = int(match[1]), len(header)
            if total > MAX_BYTES:
                raise ValueError('public package-name list is too large')
            while True:
                row = source.readline(MAX_LINE_BYTES + 1)
                if not row:
                    break
                total += len(row)
                if total > MAX_BYTES:
                    raise ValueError('public package-name list is too large')
                if len(row) > MAX_LINE_BYTES or not row.endswith(b'\n'):
                    raise ValueError('invalid public package-name list')
                body = row[:-1]
                raw_eco, separator, raw_name = body.partition(b'\t')
                if (not separator or not raw_eco or not raw_name or len(raw_eco) > 800 or
                        len(raw_name) > 2048 or previous is not None and body <= previous):
                    raise ValueError('invalid public package-name list')
                if raw_eco != previous_eco:
                    eco = raw_eco.decode('utf-8')
                    if len(eco) > 200 or not eco.isprintable() and _CONTROL.search(eco):
                        raise ValueError('invalid public package-name list')
                    previous_eco = raw_eco
                    bucket = selected.setdefault(eco, set()) if eco in needed else None
                name = raw_name.decode('utf-8')
                if len(name) > 512 or not name.isprintable() and _CONTROL.search(name):
                    raise ValueError('invalid public package-name list')
                if bucket is not None:
                    bucket.add(canonical(eco, name))
                previous = body
        return revision, selected
    except (UnicodeError, EOFError, zlib.error) as error:
        raise ValueError('invalid public package-name list') from error


@contextmanager
def cache_lock(path, exclusive):
    flags = os.O_RDWR | os.O_CREAT if exclusive else os.O_RDONLY
    fd = os.open(str(path) + '.lock', flags, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _digest(source):
    digest = hashlib.sha256()
    while True:
        part = source.read(64 * 1024)
        if not part:
            source.seek(0)
            return digest.hexdigest()
        digest.update(part)


def read_cache(path, url):
    source = None
    try:
        # The lease is opened while writers cannot unlink its generation.
        # It remains readable after a newer generation replaces the manifest.
        with cache_lock(path, False):
            with Path(str(path) + '.meta.json').open() as manifest:
                raw = manifest.read(4097)
            if len(raw) > 4096:
                return None
            saved = json.loads(raw)
            if (set(saved) != {'format', 'url', 'etag', 'sha256', 'revision'} or saved['format'] != 2 or
                    saved['url'] != url or not isinstance(saved['etag'], str) or len(saved['etag']) > 512 or
                    _CONTROL.search(saved['etag']) or not isinstance(saved['sha256'], str) or
                    not re.fullmatch('[0-9a-f]{64}', saved['sha256']) or type(saved['revision']) is not int or
                    not 0 <= saved['revision'] < 2 ** 63):
                return None
            blob = Path(str(path) + '.' + saved['sha256'] + '.gz')
            source = blob.open('rb')
        if os.fstat(source.fileno()).st_size > MAX_BYTES or _digest(source) != saved['sha256']:
            source.close()
            return None
        return dict(saved, path=blob, file=source)
    except (OSError, ValueError, TypeError, KeyError):
        if source is not None:
            source.close()
        return None


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def write_cache(path, saved):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = Path(str(path) + '.meta.json')
    blob = Path(str(path) + '.' + saved['sha256'] + '.gz')
    fd, temporary = tempfile.mkstemp(prefix='.public-names-meta-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as target:
            json.dump({key: saved[key] for key in ('format', 'url', 'etag', 'sha256', 'revision')},
                      target, ensure_ascii=False, separators=(',', ':'))
            target.write('\n')
        with cache_lock(path, True):
            old = None
            try:
                with manifest.open() as previous:
                    record = json.loads(previous.read(4097))
                if re.fullmatch('[0-9a-f]{64}', record.get('sha256', '')):
                    old = Path(str(path) + '.' + record['sha256'] + '.gz')
            except (OSError, ValueError, TypeError, AttributeError):
                pass
            try:
                os.replace(saved['path'], blob)
                # Only this atomic pointer commits the bytes and their ETag.
                os.replace(temporary, manifest)
            except OSError:
                if blob != old:
                    _unlink(blob)
                raise
            # Writers serialize publication and cleanup. Readers already own
            # an open lease, so unlinking an old Linux inode is safe.
            prefix = path.name + '.'
            for candidate in path.parent.iterdir():
                if (candidate != blob and candidate.name.startswith(prefix) and
                        re.fullmatch('[0-9a-f]{64}\\.gz', candidate.name[len(prefix):])):
                    _unlink(candidate)
    finally:
        _unlink(temporary)


def read_response(response, deadline, target):
    """Copy exact gzip bytes to disk without assembling the response in memory."""
    size, digest = 0, hashlib.sha256()
    read = getattr(response, 'read1', response.read)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('public package-name download timed out')
        sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
        if sock is not None:
            sock.settimeout(remaining)
        part = read(min(64 * 1024, MAX_BYTES + 1 - size))
        if not part:
            return digest.hexdigest()
        size += len(part)
        if size > MAX_BYTES:
            raise ValueError('public package-name list is too large')
        target.write(part)
        digest.update(part)


def download(url, headers, cafile, deadline, directory):
    """Bound DNS/TLS/body together; abandoned workers never publish their temporary file."""
    result, cancelled = queue.Queue(maxsize=1), threading.Event()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.public-names-', dir=str(directory))
    except OSError:
        fd, temporary = tempfile.mkstemp(prefix='.public-names-')

    def fetch():
        success = False
        try:
            with os.fdopen(fd, 'wb') as target:
                context = ssl.create_default_context(cafile=cafile) if cafile else None
                req = urllib.request.Request(url, headers=headers, method='GET')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('public package-name download timed out')
                with urllib.request.urlopen(req, timeout=remaining, context=context) as response:
                    digest = read_response(response, deadline, target)
                    etag = response.headers.get('ETag', '')
                    if len(etag) > 512 or _CONTROL.search(etag):
                        etag = ''
            if not cancelled.is_set():
                result.put((True, {'format': 2, 'url': url, 'etag': etag, 'sha256': digest,
                                   'path': Path(temporary)}))
                success = True
        except Exception as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            result.put((False, error))
        finally:
            if not success or cancelled.is_set():
                _unlink(temporary)

    threading.Thread(target=fetch, name='patchfirst-public-names', daemon=True).start()
    try:
        success, value = result.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        cancelled.set()
        _unlink(temporary)
        raise TimeoutError('public package-name download timed out') from None
    if not success:
        raise value
    return value


def load(api, cache=None, *, cafile=None, offline=False, fallback=False, needed=()):
    """Download one common file, then select ecosystems locally; no selectors leave the owner."""
    use(None)
    if offline:
        return None
    path = Path(cache) if cache is not None else default_cache()
    with ExitStack() as leases:
        origins = [api.rstrip('/')]
        if fallback and origins[0] == DEFAULT_API:
            origins.append(FALLBACK_API)
        saved, selection = None, None
        from uplink import USER_AGENT
        deadline = time.monotonic() + TOTAL_TIMEOUT
        for origin in origins:
            url = origin + '/agent/public-names.json.gz'
            cached = read_cache(path, url)
            if cached is not None:
                leases.enter_context(cached['file'])
            saved = saved or cached
            headers = {'User-Agent': USER_AGENT, 'Accept-Encoding': 'gzip'}
            if cached and cached['etag']:
                headers['If-None-Match'] = cached['etag']
            incoming = None
            try:
                if os.environ.get('PSR_OFFLINE') == '1':
                    raise OSError('network disabled')
                request_deadline = min(deadline, time.monotonic() + REQUEST_TIMEOUT)
                if request_deadline <= time.monotonic():
                    continue
                incoming = download(url, headers, cafile, request_deadline, path.parent)
                revision, selection = read_list(incoming['path'], needed)
                incoming['revision'] = revision
                try:
                    write_cache(path, incoming)
                except OSError:
                    pass
                break
            except urllib.error.HTTPError as error:
                not_modified = error.code == 304 and cached is not None
                error.close()
                if not_modified:
                    try:
                        _, selection = read_list(cached['file'], needed)
                        break
                    except (OSError, ValueError):
                        saved = None
            except (OSError, ValueError, EOFError, http.client.HTTPException):
                pass
            finally:
                if incoming is not None:
                    _unlink(incoming['path'])
        if selection is None and saved is not None:
            try:
                _, selection = read_list(saved['file'], needed)
            except (OSError, ValueError):
                pass
        if selection is None:
            print(t('patchfirst: {message}', message=t('could not obtain the public package-name list: '
                  'components outside the catalogue were not checked')), file=sys.stderr)
        use(selection)
        return selection
