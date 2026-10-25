"""Exact dependencies from lock files without running project code."""
import json
import hashlib
import re
from urllib.parse import urlsplit
import fnmatch

MAX_PACKAGES = 20000
NPM_NAME = re.compile(r'(?:@[a-z0-9_.~-]+/)?[a-z0-9_.~-]+', re.I)
PYPI_NAME = re.compile(r'[a-z0-9][a-z0-9._-]*', re.I)
VERSION = re.compile(r'[0-9][a-z0-9.!+_~-]{0,127}', re.I)


def exact(version):
    return isinstance(version, str) and bool(VERSION.fullmatch(version))


def public_registry(value, eco):
    """Only the ecosystem's own HTTPS registry, without embedded credentials."""
    if not isinstance(value, str):
        return False
    try:
        url = urlsplit(value)
        hosts = {'registry.npmjs.org'} if eco == 'npm' else {'pypi.org', 'files.pythonhosted.org'}
        return url.scheme == 'https' and url.hostname in hosts and not url.username and not url.password and url.port in (None, 443)
    except ValueError:
        return False


def row(eco, name, version, dev=False, private=False):
    pattern = NPM_NAME if eco == 'npm' else PYPI_NAME
    if not isinstance(name, str) or not pattern.fullmatch(name) or (not private and not exact(version)):
        return None
    result = {'eco': eco, 'name': name.lower(), 'version': version if exact(version) else '0'}
    if private:
        result['private'] = True
    if dev:
        result['dev'] = True
    return result


def npm_json(data):
    if isinstance(data.get('packages'), dict):
        for path, package in data['packages'].items():
            if not path or not isinstance(package, dict):
                continue
            name = package.get('name') or path.rsplit('node_modules/', 1)[-1]
            private = package.get('link') or not path.startswith('node_modules/') and '/node_modules/' not in path
            private = private or not public_registry(package.get('resolved'), 'npm')
            yield row('npm', name, package.get('version'), package.get('dev') or package.get('devOptional'), private)
        return
    pending = [(data.get('dependencies', {}), False)]
    while pending:
        packages, parent_dev = pending.pop()
        if not isinstance(packages, dict):
            continue
        for name, package in packages.items():
            if isinstance(package, dict):
                dev = parent_dev or package.get('dev')
                yield row('npm', name, package.get('version'), dev, not public_registry(package.get('resolved'), 'npm'))
                pending.append((package.get('dependencies', {}), dev))


def yarn(text):
    blocks = re.split(r'(?=^[^\s#].*:\s*$)', text, flags=re.M)
    for block in blocks:
        lines = block.splitlines()
        if not lines or not lines[0].rstrip().endswith(':'):
            continue
        key = lines[0].strip().rstrip(':').strip('"\'')
        names = re.findall(r'(?:^|,\s*["\']?)((?:@[^/\s]+/)?[^@\s,"\']+)@', key)
        version = re.search(r'^\s+version(?::|\s)\s*["\']?([^"\'\s]+)', block, re.M)
        resolution = re.search(r'^\s+resolution:\s*["\']?(.+?)["\']?\s*$', block, re.M)
        resolved = re.search(r'^\s+resolved\s+["\']?([^"\'\s]+)', block, re.M)
        private = not (resolved and (public_registry(resolved[1], 'npm') or
                       public_registry(resolved[1].replace('://registry.yarnpkg.com/', '://registry.npmjs.org/'), 'npm')))
        if re.search(r'@(?:file|git\+ssh|git\+https|https?|github|workspace|portal|link):', key):
            private = True
        if resolution:
            match = re.match(r'((?:@[^/]+/)?[^@]+)@([^:]+):', resolution[1])
            if match:
                private = match[2] != 'npm'
                names = [match[1]]
            else:
                private = True
        elif '@npm:' in key:
            names = re.findall(r'@npm:((?:@[^/\s]+/)?[^@\s,"\']+)@', key)
        if version or private:
            for name in names:
                yield row('npm', name, version[1] if version else None, private=private)


def pnpm(text):
    active, current = False, None
    for line in text.splitlines():
        if line and not line[0].isspace():
            if current:
                yield current
                current = None
            active = line.strip() == 'packages:'
        if not active:
            continue
        key = re.match(r'^  ["\']?(.+?)["\']?:\s*$', line)
        if key:
            if current:
                yield current
            value = key[1].lstrip('/').split('(')[0]
            match = re.fullmatch(r'((?:@[^/]+/)?[^/@]+)(?:/|@)([^/]+)', value)
            current = row('npm', match[1], match[2].split('_', 1)[0]) if match else None
        elif current and re.match(r'\s+dev:\s*true\s*$', line):
            current['dev'] = True
        elif current and 'tarball:' in line:
            tarball = re.search(r'tarball:\s*["\']?([^\s,}\'\"]+)', line)
            if not tarball or not public_registry(tarball[1], 'npm'):
                current['private'] = True
    if current:
        yield current


def python_toml(text):
    """Read only package scalars; the format also works with the agent's Python 3.8."""
    for block in re.split(r'^\[\[package\]\]\s*$', text, flags=re.M)[1:]:
        head = re.split(r'^\[package\.', block, maxsplit=1, flags=re.M)[0]
        fields = dict(re.findall(r'^([\w-]+)\s*=\s*["\']([^"\'\n]*)["\']\s*$', head, re.M))
        dev = fields.get('category') == 'dev'
        groups = re.search(r'^groups\s*=\s*\[([^]]*)\]', block, re.M)
        if groups:
            dev = 'main' not in re.findall(r'["\']([^"\']+)["\']', groups[1])
        source = re.search(r'^source\s*=\s*\{([^}]*)\}', block, re.M)
        private = False
        if source:
            registry = re.search(r'\bregistry\s*=\s*["\']([^"\']+)', source[1])
            private = not registry or not public_registry(registry[1], 'PyPI')
        table = re.search(r'^\[package.source\]\s*\n(.*?)(?=^\[|\Z)', block, re.M | re.S)
        if table:
            private = True
        yield row('PyPI', fields.get('name'), fields.get('version'), dev, private)


def requirements(text, dev=False):
    # Index options apply to the entire file, including lines preceding the option.
    indexes = re.findall(r'(?:^|\s)(?:--(?:extra-)?index-url|--find-links)(?:\s+|=)(\S+)', text)
    indexes += re.findall(r'(?:^|\s)-(?:i|f)(?:\s+|=)?(\S+)', text)
    private_index = any(not public_registry(url, 'PyPI') for url in indexes)
    private_index = private_index or '--no-index' in text
    for line in text.replace('\\\n', ' ').splitlines():
        match = re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w, .-]+\])?\s*==\s*([^\s;#]+)(.*)$', line)
        if match and (not match[3].strip() or match[3].lstrip().startswith((';', '#', '--hash='))):
            yield row('PyPI', match[1], match[2], dev, private_index)
        elif line.strip() and (line.lstrip().startswith('--editable') or
                              not line.lstrip().startswith(('#', '--', '-r', '-c', '-i', '-f'))):
            editable = r'^\s*(?:-e(?:\s+|=)?|--editable(?:\s+|=))'
            value = re.sub(editable, '', line).strip()
            direct = re.search(r'(?:\s@\s|://|^[^\s]+/|^file:|^git\+|#egg=|\.(?:whl|zip|tar(?:\.gz|\.bz2|\.xz)?)(?:$|#))', value)
            if re.match(editable, line) or direct:
                name = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s', value)
                egg = re.search(r'#egg=([A-Za-z0-9][A-Za-z0-9._-]*)', value)
                local_name = name[1] if name else egg[1] if egg else 'local-' + hashlib.sha256(value.encode()).hexdigest()[:12]
                yield row('PyPI', local_name, None, dev, True)


def development(rows, prod, dev, graph):
    def closure(roots):
        seen, pending = set(), list(roots)
        while pending:
            name = pending.pop().lower()
            if name not in seen:
                seen.add(name)
                pending.extend(graph.get(name, ()))
        return seen
    dev_only = closure(dev) - closure(prod)
    for package in rows:
        if package['name'] in dev_only:
            package['dev'] = True
    return rows


def yaml_development(rows, text, manifest=None):
    prod, dev, graph = set(), set(), {}
    if manifest:
        prod.update(manifest.get('dependencies', {}))
        prod.update(manifest.get('optionalDependencies', {}))
        dev.update(manifest.get('devDependencies', {}))
    current, section, group = [], '', ''
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.rstrip(':').strip()
            if section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                group = section
            if line.rstrip().endswith(':') and '@' in line:
                current = re.findall(r'(?:^|,\s*["\']?)((?:@[^/\s]+/)?[^@\s,"\']+)@',
                                     line.rstrip(':').strip('"\''))
        if section == 'importers':
            match = re.match(r'^    (dependencies|devDependencies|optionalDependencies):', line)
            if match:
                group = match[1]
            match = re.match(r'^      ["\']?((?:@[^/]+/)?[^:\s"\']+)["\']?:', line)
            if match:
                (dev if group == 'devDependencies' else prod).add(match[1])
        elif section in ('dependencies', 'devDependencies', 'optionalDependencies'):
            match = re.match(r'^  ["\']?((?:@[^/]+/)?[^:\s"\']+)["\']?:', line)
            if match:
                (dev if section == 'devDependencies' else prod).add(match[1])
        if section in ('packages', 'snapshots'):
            match = re.match(r'^  ["\']?(.+?)["\']?:', line)
            if match:
                value = match[1].lstrip('/').split('(')[0]
                found = re.match(r'((?:@[^/]+/)?[^/@]+)(?:/|@)', value)
                current = [found[1]] if found else []
            match = re.match(r'^      ["\']?((?:@[^/]+/)?[^:\s"\']+)["\']?:', line)
        else:
            match = re.match(r'^    ["\']?((?:@[^/]+/)?[^:\s"\']+)["\']?(?::|\s)', line)
        if match:
            for name in current:
                graph.setdefault(name.lower(), set()).add(match[1].lower())
    return development(rows, prod, dev, graph)


def uv_development(rows, text):
    prod, dev, graph = set(), set(), {}
    for block in re.split(r'^\[\[package\]\]\s*$', text, flags=re.M)[1:]:
        name = re.search(r'^name\s*=\s*"([^"\n]+)"', block, re.M)
        if not name:
            continue
        sections = re.split(r'^(\[package[^\n]*\])\s*$', block, flags=re.M)
        children = set(re.findall(r'\{\s*name\s*=\s*"([^"\n]+)"', sections[0]))
        graph[name[1].lower()] = children
        local = re.search(r'^source\s*=\s*\{\s*(?:virtual|editable|directory)\s*=', sections[0], re.M)
        if local:
            prod.update(children)
        for i in range(1, len(sections), 2):
            if sections[i] == '[package.dev-dependencies]':
                dev.update(re.findall(r'\{\s*name\s*=\s*"([^"\n]+)"', sections[i + 1]))
    return development(rows, prod, dev, graph)


def workspace_manifest(root, manifests):
    """Yarn shares a lock: each workspace's runtime dependencies are prod roots."""
    manifest = manifests.get(root)
    if not manifest:
        return manifest
    patterns = manifest.get('workspaces', [])
    if isinstance(patterns, dict):
        patterns = patterns.get('packages', [])
    if not isinstance(patterns, list):
        return manifest
    merged = dict(manifest)
    for group in ('dependencies', 'optionalDependencies', 'devDependencies'):
        merged[group] = dict(manifest.get(group, {}))
    prefix = root.rstrip('/') + '/'
    for path, workspace in manifests.items():
        if not path.startswith(prefix):
            continue
        relative = path[len(prefix):]
        if any(isinstance(pattern, str) and fnmatch.fnmatchcase(relative, pattern.rstrip('/'))
               for pattern in patterns):
            for group in ('dependencies', 'optionalDependencies', 'devDependencies'):
                merged[group].update(workspace.get(group, {}))
    return merged


def private_registry_config(filename, text):
    """Return only scope/privacy decisions; callers never keep registry secrets."""
    name = filename.rsplit('/', 1)[-1]
    rules = {}
    if name not in ('.npmrc', '.yarnrc', '.yarnrc.yml'):
        return rules
    def assign(scope, value):
        public = public_registry(value, 'npm') or (name.startswith('.yarnrc') and
            public_registry(value.replace('://registry.yarnpkg.com/', '://registry.npmjs.org/'), 'npm'))
        rules[scope] = not public
    if name != '.yarnrc.yml':
        for match in re.finditer(r"^\s*(?:(@[a-z0-9_.~-]+):)?registry\s*(?:=|\s)\s*[\"']?([^\s\"'#]*)", text, re.M | re.I):
            assign((match[1] or '*').lower(), match[2])
    else:
        in_scopes, scope = False, None
        for line in text.splitlines():
            if line and not line[0].isspace() and not line.startswith('#'):
                in_scopes, scope = line.strip() == 'npmScopes:', None
            if in_scopes:
                match = re.match(r"^\s+[\"']?@?([a-z0-9_.~-]+)[\"']?:\s*$", line, re.I)
                if match:
                    scope = '@' + match[1].lower()
            match = re.match(r"^(\s*)npmRegistryServer\s*:\s*[\"']?([^\s\"'#]+)", line)
            if match:
                assign(scope if in_scopes and scope else '*', match[2])
    return rules


def parse(filename, text, manifest=None):
    name = filename.rsplit('/', 1)[-1]
    try:
        if name == 'package-lock.json':
            rows = npm_json(json.loads(text))
        elif name == 'Pipfile.lock':
            data = json.loads(text)
            sources = {s.get('name'): s.get('url') for s in data.get('_meta', {}).get('sources', []) if isinstance(s, dict)}
            private_default = any(not public_registry(url, 'PyPI') for url in sources.values())
            rows = (row('PyPI', n, p.get('version', '')[2:], group == 'develop')
                    if not (set(p) & {'git', 'path', 'file', 'ref', 'editable'} or
                            (not p.get('index') and private_default) or (p.get('index') and (p['index'] != 'pypi' or
                             p['index'] in sources and not public_registry(sources[p['index']], 'PyPI'))))
                    else row('PyPI', n, p.get('version', '')[2:], group == 'develop', True)
                    for group in ('default', 'develop') for n, p in data.get(group, {}).items()
                    if isinstance(p, dict))
        elif name == 'yarn.lock':
            rows = yarn(text)
        elif name == 'pnpm-lock.yaml':
            rows = pnpm(text)
        elif name in ('poetry.lock', 'uv.lock'):
            rows = python_toml(text)
        elif name.startswith('requirements') and name.endswith('.txt'):
            rows = requirements(text, 'dev' in name.lower())
        elif name == 'METADATA':
            fields = dict(re.findall(r'^(Name|Version):\s*([^\n\r]+)', re.split(r'\r?\n\r?\n', text, maxsplit=1)[0], re.M))
            # Installed distributions are public unless local collection found source evidence.
            private = bool(re.search(r'^PSR-Private: (?:direct|index)$', text, re.M))
            rows = [row('PyPI', fields.get('Name'), fields.get('Version'), private=private)]
        else:
            rows = []
        result = [r for r in rows if r]
        if name in ('yarn.lock', 'pnpm-lock.yaml'):
            result = yaml_development(result, text, manifest)
        elif name == 'uv.lock':
            result = uv_development(result, text)
        return result
    except (ValueError, TypeError, AttributeError, RecursionError):
        return []


def collect(files, limit=MAX_PACKAGES, npm_registry=()):
    result, seen, manifests = [], {}, {}
    files = list(files)
    registry_rules = [(path.rpartition('/')[0], private_registry_config(path, text))
                      for path, text in files if private_registry_config(path, text)]
    # Remote collection sends only decisions, scoped to the exact lock path.
    remote_rules = {}
    for line in npm_registry:
        parts = line.split('\t')
        if len(parts) == 3 and parts[2] in ('private', 'public'):
            remote_rules.setdefault(parts[0], {})[parts[1]] = parts[2] == 'private'
    registry_rules.sort(key=lambda item: len(item[0]))
    for path, text in files:
        if path.endswith('/package.json'):
            try:
                manifest = json.loads(text)
                if isinstance(manifest, dict):
                    manifests[path.rsplit('/', 1)[0]] = manifest
            except ValueError:
                pass
    for path, text in files:
        root = path.rpartition('/')[0]
        manifest = workspace_manifest(root, manifests) if path.endswith('/yarn.lock') else manifests.get(root)
        for package in parse(path, text, manifest):
            if package['eco'] == 'npm':
                scope = package['name'].split('/', 1)[0] if package['name'].startswith('@') else '*'
                rules = {}
                for config_root, config in registry_rules:
                    if root == config_root or root.startswith(config_root.rstrip('/') + '/'):
                        rules.update(config)
                rules.update(remote_rules.get(path, {}))
                if rules.get(scope, rules.get('*', False)):
                    package['private'] = True
            key = (path, package['eco'], package['name'], package['version'], package.get('dev', False))
            if key in seen:
                if package.get('private'):
                    result[seen[key]]['private'] = True
                continue
            if len(result) >= limit:
                return result, True
            seen[key] = len(result)
            result.append(dict(package, lock=path))
    # A private lock identifies a package by name, independently of installed version.
    # Unpinned requirements still establish names when their primary index is private.
    private_names = {}
    normalize = lambda name: re.sub(r'[-_.]+', '-', name).lower()
    for package in result:
        basename = package['lock'].rsplit('/', 1)[-1]
        if (package['eco'] == 'PyPI' and package.get('private') and basename != 'METADATA'
                and not (basename.startswith('requirements') and basename.endswith('.txt'))):
            private_names.setdefault(package['lock'].rsplit('/', 1)[0], set()).add(normalize(package['name']))
    for path, text in files:
        name = path.rsplit('/', 1)[-1]
        if not (name.startswith('requirements') and name.endswith('.txt')):
            continue
        # extra-index is ambiguous: these names may still have come from PyPI.
        # Only an explicitly private primary index establishes provenance here.
        indexes = re.findall(r'(?:^|\s)(?:--index-url(?:\s+|=)|-i(?:\s+|=)?)(\S+)', text)
        if indexes and not public_registry(indexes[-1], 'PyPI'):
            names = re.findall(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?=\s|[<>=!~\[]|$)', text, re.M)
            private_names.setdefault(path.rsplit('/', 1)[0], set()).update(map(normalize, names))
    for package in result:
        if package['eco'] != 'PyPI' or not package['lock'].endswith('/METADATA'):
            continue
        name = normalize(package['name'])
        parent = package['lock'].rsplit('/', 1)[0]
        while parent:
            if name in private_names.get(parent, ()):
                package['private'] = True
                break
            parent = parent.rsplit('/', 1)[0] if '/' in parent else ''
    return result, False
