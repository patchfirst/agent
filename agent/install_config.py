"""Shared config validation and installation preparation for zipapp or binary."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile

# Same as uplink.USER_AGENT: the installer runs separately from the agent package.
UA = 'psr/1.0 (+security inventory) patchfirst/1.1.1'


def canonical_config(config):
    """Only standard paths participate in migration; --config custom stays unchanged."""
    if config == '/etc/psr-agent.json':
        return '/etc/patchfirst.json'
    suffix = '/.local/share/psr/psr-agent.json'
    if config.endswith(suffix):
        return config[:-len(suffix)] + '/.local/share/patchfirst/patchfirst.json'
    return config


@contextlib.contextmanager
def runtime_config(config):
    canonical = canonical_config(config)
    if (canonical == config and config != '/etc/patchfirst.json' and
            not config.endswith('/.local/share/patchfirst/patchfirst.json')):
        # Custom registries keep their original read-only where semantics.
        yield config
        return
    lock = Path(canonical + '.migration.lock')
    if not lock.parent.exists():
        lock = Path(config + '.migration.lock')
    # Hold the directory fd: neither symlink replacement nor parent renaming
    # must redirect root to another lock/state. In user
    # directories, root does not participate in the migration protocol at all.
    with contextlib.ExitStack() as stack:
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        stack.callback(os.close, directory)
        # For users, /home and other ancestors may be symlinks (Atomic).
        # Root traverses each original component without following symlinks.
        parent = lock.parent.resolve() if os.geteuid() != 0 else lock.parent.absolute()
        for part in parent.parts[1:]:
            directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            stack.callback(os.close, directory)
            if os.geteuid() == 0 and os.fstat(directory).st_uid != 0:
                yield config
                return
        fd = os.open(lock.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        handle = stack.enter_context(os.fdopen(fd, 'a'))
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise PermissionError('unsafe migration lock owner or type')
        os.fchmod(handle.fileno(), 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        state = Path(canonical + '.migration.json')
        # The lock may be at the legacy path if the canonical path does not exist yet.
        state_name = state.name if lock.parent == state.parent else None
        try:
            state_fd = (os.open(state_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                        if state_name else None)
        except FileNotFoundError:
            state_fd = None
        if state_fd is not None:
            with os.fdopen(state_fd) as active:
                metadata = os.fstat(active.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                    raise PermissionError('unsafe migration state owner or type')
                config = json.load(active)['active']
        elif canonical != config and not Path(config).exists() and Path(canonical).exists():
            config = canonical
        yield config


def reject_legacy_schedule(config):
    """After rollback, an old installer may restore a second sender with a different secret."""
    canonical = canonical_config(config)
    if canonical != config and not Path(canonical).exists():
        return  # The old cached installer has only created the legacy installation so far.
    jobs = {name: Path('/etc/cron.d/' + name).exists() for name in ('patchfirst', 'psr-agent')}
    if not all(jobs.values()) and shutil.which('crontab'):
        try:
            current = subprocess.run(['crontab', '-l'], text=True, capture_output=True, timeout=10)
        except subprocess.TimeoutExpired as error:
            raise OSError('crontab -l did not respond within 10 s') from error
        for row in current.stdout.splitlines():
            if row.strip() and not row.lstrip().startswith('#'):
                for name in jobs:
                    jobs[name] = jobs[name] or bool(re.search(r'# %s\s*$' % name, row))
    if all(jobs.values()):
        raise ValueError('two cron jobs found: patchfirst and psr-agent; sending canceled: '
                         'reinstall using the command from the dashboard to keep a single job')


def defer_runtime_directory_cleanup(runtime):
    """The bootloader removes the runtime after exit; the helper only removes the empty directory."""
    env = dict(os.environ)
    if 'LD_LIBRARY_PATH_ORIG' in env:
        env['LD_LIBRARY_PATH'] = env.pop('LD_LIBRARY_PATH_ORIG')
    else:
        env.pop('LD_LIBRARY_PATH', None)
    subprocess.run(['/bin/sh', '-c',
                    '(n=0; while [ -d "$1" ] && [ "$n" -lt 1200 ]; do '
                    'sleep .1; n=$((n + 1)); done; rmdir -- "$2" 2>/dev/null || :) &',
                    'patchfirst-cleanup', str(runtime), str(runtime.parent)],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, start_new_session=True, env=env, check=True)


def _ancestors():
    result = {os.getpid()}
    pid = os.getppid()
    while pid > 1 and pid not in result:
        result.add(pid)
        try:
            pid = int(Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return result


def drain(executables, timeout=120):
    """After installing bridges, wait for legacy code still in gather."""
    excluded = _ancestors()
    targets = set(str(path) for path in executables)
    deadline = time.monotonic() + timeout
    while True:
        running = False
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) in excluded:
                continue
            try:
                argv = (proc / 'cmdline').read_bytes().split(b'\0')[:2]
                executable = os.readlink(str(proc / 'exe')).replace(' (deleted)', '')
                if executable in targets or any(os.fsdecode(arg) in targets or
                                                os.path.realpath(os.fsdecode(arg)) in targets for arg in argv):
                    running = True
                    break
            except (OSError, ProcessLookupError):
                pass
        if not running:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError('waiting for the running agent exceeded %s seconds; cleanup canceled, retry after the agent finishes' % timeout)
        time.sleep(.05)


def atomic_text(path, text, mode=0o600):
    temporary = path.with_name('.' + path.name + '.new')
    temporary.write_text(text)
    temporary.chmod(mode)
    os.replace(temporary, path)


def stage_bridges(work, previous, canonical, folder):
    """New calls through legacy paths wait for the lock; already running legacy code can be drained."""
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    for name in ('patchfirst.pyz', 'patchfirst'):
        source = Path(work, name)
        if source.exists():
            temporary = folder / ('.' + name + '.new')
            shutil.copyfile(source, temporary)
            temporary.chmod(0o700)
            os.replace(temporary, folder / name)
    state = Path(canonical + '.migration.json')
    if not state.exists():
        active = previous if Path(previous).exists() else canonical
        atomic_text(state, json.dumps({'active': active}) + '\n')
    executable = str(folder / 'patchfirst')
    legacy_folder = Path(previous).parent if previous != '/etc/psr-agent.json' else Path('/opt/psr')
    paths = [legacy_folder / 'psr-agent', legacy_folder / 'psr-agent.pyz']
    for path in paths:
        if not path.exists():
            continue
        if path.suffix == '.pyz':
            code = 'import os, sys\nos.environ["TMPDIR"] = %r\nos.execv(%r, [%r, "migration-run", %r, %r] + sys.argv[1:])\n' % (
                str(folder), executable, executable, previous, canonical)
        else:
            code = '#!/bin/sh\nTMPDIR=%s\nexport TMPDIR\nexec %s migration-run %s %s "$@"\n' % tuple(
                shlex.quote(value) for value in (str(folder), executable, previous, canonical))
        atomic_text(path, code, 0o700)
    return paths


def origin(value):
    """Validate the API URL and extract the agent download origin."""
    api = urllib.parse.urlsplit(value)
    if api.scheme not in ('https', 'http') or not api.hostname or api.username or api.password:
        raise ValueError('an http(s) API URL without a username is required')
    if api.query or api.fragment:
        raise ValueError('the API URL must not contain a query or fragment')
    if api.scheme == 'http' and api.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('HTTPS is required for a remote API')
    return urllib.parse.urlunsplit((api.scheme, api.netloc, '', '', ''))


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('config must be an object')
    for field in ('api', 'fleet', 'token', 'secret', 'host', 'host_uuid'):
        if not isinstance(config.get(field), str) or not config[field]:
            raise ValueError('missing field ' + field)
    origin(config['api'])
    return config


def previous_config(path):
    """A corrupted previous installation does not prevent a fresh installation."""
    try:
        return validate_config(json.loads(Path(path).read_text()))
    except (OSError, ValueError, TypeError):
        return None


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Do not redirect the agent download request to a different origin."""
    def redirect_request(self, request, response, code, message, headers, new_url):
        if origin(new_url) != origin(request.full_url):
            raise ValueError('the agent must be downloaded from the API domain')
        return super().redirect_request(request, response, code, message, headers, new_url)


def download_agent(config, work, mode):
    """Prepare the zipapp or verify the bootstrap binary using config.api and config.ca."""
    source = origin(config['api'])
    context = ssl.create_default_context(cafile=config.get('ca'))
    opener = urllib.request.build_opener(SameOriginRedirect(), urllib.request.HTTPSHandler(context=context))
    opener.addheaders = [('User-Agent', UA)]

    def fetch(name, limit):
        with opener.open(source + '/agent/' + name, timeout=60) as response:
            data = response.read(limit + 1)
        if not data or len(data) > limit:
            raise ValueError('invalid agent size')
        return data

    if mode == 'python':
        target = Path(work, 'patchfirst.pyz')
        target.write_bytes(fetch('patchfirst.pyz', 16 * 1024 * 1024))
        if not zipfile.is_zipfile(target):
            raise ValueError('the downloaded agent is not a zip archive')
    else:
        artifact = os.environ['PSR_BOOTSTRAP_ARTIFACT']
        if artifact not in ('patchfirst-linux-x86_64', 'patchfirst-linux-x86_64-musl',
                            'psr-agent-linux-x86_64', 'psr-agent-linux-x86_64-musl'):
            raise ValueError('invalid binary name')
        target = Path(work, 'psr-agent' if artifact.startswith('psr-agent-') else 'patchfirst')
        size = target.stat().st_size
        if not 0 < size <= 64 * 1024 * 1024:
            raise ValueError('invalid agent size')
        digest = hashlib.sha256()
        with target.open('rb') as agent:
            for chunk in iter(lambda: agent.read(64 * 1024), b''):
                digest.update(chunk)
        sums = fetch('SHA256SUMS', 16384).decode('ascii')
        matches = [line.split()[0] for line in sums.splitlines()
                   if len(line.split()) == 2 and line.split()[1] == artifact]
        if matches != [digest.hexdigest()]:
            raise ValueError('SHA-256 mismatch, installation canceled')
        target.chmod(0o700)


def prepare(argv, mode=None):
    """Validate config from the environment and prepare it along with the cron job."""
    try:
        work, folder, config_path, root = argv
        encoded = os.environ.get('PSR_CONFIG', '')
        if encoded:
            if not re.fullmatch(r'[A-Za-z0-9_-]+', encoded):
                raise ValueError('config in b64url format is required')
            config = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        else:
            config = json.loads(Path(os.environ['PSR_EXISTING_CONFIG']).read_text())
        validate_config(config)
        previous = os.environ.get('PSR_EXISTING_CONFIG')
        old = previous_config(previous) if previous and encoded else None
        # Only updating the same server preserves HMAC labels. The region/API
        # is part of the identity: the same UUID from another service is not enough.
        if old and all(old[field] == config[field] for field in ('api', 'fleet', 'host_uuid')):
            config['secret'] = old['secret']
        source = origin(config['api'])
        bootstrap = os.environ.get('PSR_BOOTSTRAP_API')
        if bootstrap and source != origin(bootstrap):
            raise ValueError('config.api does not match the installer download URL')
        for path in (folder, config_path, sys.executable):
            if any(char in path for char in '\r\n'):
                raise ValueError('newline in path')
        if mode is None and bootstrap:
            mode = 'binary'
        if mode:
            download_agent(config, work, mode)
        legacy = os.environ.get('PSR_BOOTSTRAP_ARTIFACT', '').startswith('psr-agent-')
        name = 'psr-agent' if legacy else 'patchfirst'
        executable = [sys.executable, folder + '/patchfirst.pyz'] if mode == 'python' else [folder + '/' + name]
        if mode == 'python':
            Path(work, 'patchfirst').write_text('#!/bin/sh\nexec ' + ' '.join(
                shlex.quote(value) for value in executable) + ' "$@"\n')
        command = 'TMPDIR=' + shlex.quote(folder) + ' ' + ' '.join(shlex.quote(value) for value in (
            *executable, 'run', '--config', config_path))
        command = command.replace('%', '\\%')
        timing = os.environ.get('PSR_CRON_SCHEDULE', '')
        if timing and not re.fullmatch(r'[A-Za-z0-9*/,-]+(?: [A-Za-z0-9*/,-]+){4}|@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)', timing):
            raise ValueError('invalid cron schedule')
        timing = timing or '%d */6 * * *' % secrets.randbelow(60)
        schedule = '%s %s%s >/dev/null 2>&1 # %s\n' % (
            timing, 'root ' if root == '1' else '', command, name)
        Path(work, 'config.json').write_text(json.dumps(config, ensure_ascii=False) + '\n')
        Path(work, 'cron').write_text(schedule)
        return 0
    except Exception as error:
        print('patchfirst: installation failed: ' + str(error), file=sys.stderr)
        return 1


def lifecycle_lock_path(canonical):
    config = Path(canonical)
    parent = config.parent.parent if config.name == 'patchfirst.json' and config.parent.name == 'patchfirst' else config.parent
    return parent / '.patchfirst-lifecycle.lock'


def lifecycle_lock(stack, canonical):
    path = lifecycle_lock_path(canonical)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = stack.enter_context(path.open('a'))
    os.chmod(str(path), 0o600)
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)


def choose_registry(old_registry, registry):
    source = old_registry if old_registry.exists() else registry
    if old_registry.exists() and registry.exists():
        left = json.loads(old_registry.read_text())
        right = json.loads(registry.read_text())
        if all(right.get(path) == number for path, number in left.items()):
            return registry
        if not all(left.get(path) == number for path, number in right.items()):
            raise ValueError('project registry conflict; operation stopped')
    return source


def uninstall(purge=False, root=None):
    """Stop new calls, drain active gather calls, and save the latest registry."""
    root = os.geteuid() == 0 if root is None else root
    folder = Path('/opt/patchfirst') if root else Path.home() / '.local/share/patchfirst'
    legacy = Path('/opt/psr') if root else Path.home() / '.local/share/psr'
    config = Path('/etc/patchfirst.json') if root else folder / 'patchfirst.json'
    old_config = Path('/etc/psr-agent.json') if root else legacy / 'psr-agent.json'
    commands = Path('/usr/local/bin') if root else Path.home() / '.local/bin'
    registry = Path(str(config) + '.projects.json')
    old_registry = Path(str(old_config) + '.projects.json')
    if not purge:
        choose_registry(old_registry, registry)
    config.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        lifecycle_lock(stack, str(config))
        if root:
            for name in ('patchfirst', 'psr-agent'):
                Path('/etc/cron.d', name).unlink(missing_ok=True)
        elif shutil.which('crontab'):
            current = subprocess.run(['crontab', '-l'], text=True, capture_output=True)
            kept = '\n'.join(row for row in current.stdout.splitlines()
                             if not re.search(r'# (?:patchfirst|psr-agent)\s*$', row))
            subprocess.run(['crontab', '-'], input=kept + '\n', text=True, check=True)
        targets = []
        for directory, names in ((folder, ('patchfirst', 'patchfirst.pyz')),
                                 (legacy, ('psr-agent', 'psr-agent.pyz'))):
            for name in names:
                path = directory / name
                hidden = directory / ('.' + name + '.removing')
                targets.extend((path, hidden))
                if path.exists() or path.is_symlink():
                    os.replace(path, hidden)
        for name in ('patchfirst', 'psr-agent'):
            path = commands / name
            targets.append(path)
            path.unlink(missing_ok=True)
        drain(targets)
        # The owner may have changed unrelated jobs while waiting for gather.
        if not root and shutil.which('crontab'):
            current = subprocess.run(['crontab', '-l'], text=True, capture_output=True)
            kept = '\n'.join(row for row in current.stdout.splitlines()
                             if not re.search(r'# (?:patchfirst|psr-agent)\s*$', row))
            subprocess.run(['crontab', '-'], input=kept + '\n', text=True, check=True)
        for cfg in sorted(set((str(config), str(old_config)))):
            path = Path(cfg + '.migration.lock')
            if path.parent.exists():
                lock = stack.enter_context(path.open('a'))
                path.chmod(0o600)
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        for cfg in sorted(set((str(config), str(old_config)))):
            path = Path(cfg + '.projects.json.lock')
            if path.parent.exists():
                lock = stack.enter_context(path.open('a'))
                path.chmod(0o600)
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if not purge:
            source = choose_registry(old_registry, registry)
            state = Path(str(config) + '.migration.json')
            if state.exists():
                active = Path(json.loads(state.read_text())['active'] + '.projects.json')
                if active.exists():
                    source = active
            if source.exists() and source != registry:
                temp = registry.with_name(registry.name + '.new')
                shutil.copyfile(source, temp)
                temp.chmod(0o600)
                os.replace(temp, registry)
            if old_registry.exists():
                # Snapshot for rolling back to the old image. The new version does not write it.
                temp = old_registry.with_name(old_registry.name + '.new')
                shutil.copyfile(registry, temp)
                temp.chmod(0o400)
                os.replace(temp, old_registry)
        for cfg in (config, old_config):
            for suffix in ('', '.projects.json.lock', '.migration.lock', '.migration.json'):
                Path(str(cfg) + suffix).unlink(missing_ok=True)
        if purge:
            registry.unlink(missing_ok=True)
            old_registry.unlink(missing_ok=True)
            # The lifecycle lock path must always refer to the same inode, even after purge.
        for directory, names in ((folder, ('patchfirst', 'patchfirst.pyz', 'psr-agent')),
                                 (legacy, ('psr-agent', 'psr-agent.pyz'))):
            if not directory.is_dir() or directory.is_symlink():
                continue
            for name in names:
                for item in (directory / name, directory / ('.' + name + '.removing'),
                             directory / ('.' + name + '.new')):
                    item.unlink(missing_ok=True)
            # PyInstaller extracts the current process into the installation's TMPDIR.
            # The bootloader will remove the runtime after exit; the helper will remove the empty directory.
            expected = {registry, old_registry}
            runtime = Path(getattr(sys, '_MEIPASS', ''))
            if (getattr(sys, 'frozen', False) and runtime.parent == directory and
                    re.fullmatch(r'_MEI[A-Za-z0-9]+', runtime.name) and
                    not runtime.is_symlink() and runtime.is_dir()):
                defer_runtime_directory_cleanup(runtime)
                expected.add(runtime)
            try:
                directory.rmdir()
            except OSError:
                if set(directory.iterdir()).issubset(expected):
                    continue  # Expected rollback snapshots, not unrelated files.
                print('patchfirst: directory %s retained: contains other files' % directory,
                      file=sys.stderr)
    print('patchfirst: monitoring removed')
    return 0


def commit(argv):
    """Close legacy entrypoints, drain legacy code, then migrate the registry/cron."""
    script, previous, canonical = argv
    try:
        with contextlib.ExitStack() as stack:
            folder = Path(os.environ['install_dir'])
            folder.parent.mkdir(parents=True, exist_ok=True)
            Path(canonical).parent.mkdir(parents=True, exist_ok=True)
            lifecycle_lock(stack, canonical)
            old = Path(previous)
            new = Path(canonical)
            legacy_config = previous_config(previous) if old.exists() else None
            if legacy_config and new.exists() and not os.environ.get('PSR_CONFIG'):
                right = previous_config(canonical)
                if right and any(legacy_config[field] != right[field] for field in ('secret', 'host_uuid')):
                    raise ValueError('config conflict: secret or host_uuid; migration stopped')
            old_registry = Path(previous + '.projects.json')
            registry = Path(canonical + '.projects.json')
            def registry_source():
                return choose_registry(old_registry, registry)
            registry_source()  # A conflict must not change even the executable/cron.
            if legacy_config:
                paths = stage_bridges(Path(script).parent, previous, canonical, folder)
                drain(paths)
            configs_for_lock = (previous, canonical) if legacy_config else (canonical,)
            for config in sorted(set(configs_for_lock)):
                path = Path(config + '.migration.lock')
                if path.parent.exists():
                    lock = stack.enter_context(path.open('a'))
                    path.chmod(0o600)
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            for config in sorted(set(configs_for_lock)):
                path = Path(config + '.projects.json.lock')
                if path.parent.exists():
                    lock = stack.enter_context(path.open('a'))
                    path.chmod(0o600)
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            source = registry_source()
            state = Path(canonical + '.migration.json')
            if state.exists():
                active = json.loads(state.read_text())['active']
                if Path(active + '.projects.json').exists():
                    source = Path(active + '.projects.json')
            env = dict(os.environ, PSR_QUOTED_INSTALL_DIR=shlex.quote(str(folder)),
                       PSR_QUOTED_EXECUTABLE=shlex.quote(str(folder / 'patchfirst')),
                       PSR_REGISTRY_SOURCE=str(source),
                       PSR_LEGACY_CONFIG_VALID='1' if legacy_config else '0')
            Path(script).with_name('cutover.json').write_text(json.dumps({'active': canonical}) + '\n')
            return subprocess.run(['/bin/sh', script], env=env).returncode
    except (OSError, ValueError, KeyError) as error:
        print('patchfirst: installation failed: ' + str(error), file=sys.stderr)
        return 1
