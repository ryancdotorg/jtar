#!/usr/bin/env python3

import sys
import functools

from collections.abc import Iterable

__all__ = []
def export(fn):
    __all__.append(fn.__name__)
    return fn

@export
class Registrar(dict):
    def register(self, fn, name=None):
        self[name or fn.__name__] = fn
        return fn

# @functools.cache is only in Python 3.9+, so provide fall back
@export
def memoize(fn):
    return getattr(functools, 'cache', functools.lru_cache(maxsize=None))(fn)

# @functools.cached_property is only in Python 3.8+, so provide fall back
@export
def cached_property(fn):
    return getattr(functools, 'cached_property', lambda fn: property(memoize(fn)))(fn)

# recursive flatten
@export
def flatten(i, max_depth=-1):
    if max_depth != 0 and isinstance(i, Iterable) and not isinstance(i, (dict, str, bytes)):
        for s in i: yield from flatten(s, max_depth - 1)
    else: yield i

@export
def eprint(*args, **kwargs):
    if kwargs.pop('file', None):
        raise TypeError('Keyword argument `file` must be omited or `None`!')
    print(*args, file=sys.stderr, **kwargs)

