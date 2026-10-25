"""Owner-only project numbers: locked allocation and atomic private snapshots."""
import fcntl
import json
import os
import re
import tempfile

import anonymize
import uplink


def project_state_path(config):
    return os.fspath(config) + '.projects.json'


def load_projects(config):
    return load_registry(config)


def load_registry(config):
    try:
        with open(project_state_path(config)) as f:
            state = json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError as e:
        raise uplink.ApiError('invalid local project list') from e
    validate(state)
    return state


def validate(projects):
    if (not isinstance(projects, dict) or any(not isinstance(path, str) or not path or
            not isinstance(number, str) or not re.fullmatch(r'[1-9][0-9]{0,5}', number)
            for path, number in projects.items()) or len(set(projects.values())) != len(projects)):
        raise uplink.ApiError('invalid local project list')


def save_projects(config, projects):
    path = project_state_path(config)
    fd, temporary = tempfile.mkstemp(prefix='.psr-projects-', dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(projects, f, ensure_ascii=False)
            f.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(config, cfg, inv, *, load=None, save=None):
    # Agent runs retain their own flat registry and lock.
    load = load or load_projects
    save = save or save_projects
    fd = os.open(project_state_path(config) + '.lock', os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = projects = load(config)
        an = anonymize.Anonymizer(cfg['secret'], cfg.get('identity_words', []), projects=projects)
        payload = an.payload(inv)
        save(config, state)
    return payload, projects, an.labels
