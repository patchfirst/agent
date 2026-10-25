"""Public npm scopes: scoped packages outside them are treated as private names."""
import re
from functools import lru_cache

SCOPE = re.compile(r'@[a-z0-9_.~-]+')
_service_scopes = None


def use_service_catalog(scopes):
    """A running agent uses its service's catalog; without one every scope stays private."""
    global _service_scopes
    if not isinstance(scopes, list) or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes):
        raise ValueError('invalid public npm scope catalog')
    _service_scopes = frozenset(scopes)
    public_scopes.cache_clear()


@lru_cache(maxsize=1)
def public_scopes():
    return _service_scopes if _service_scopes is not None else frozenset()
