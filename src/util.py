#!/usr/bin/env python3

import sys
import operator
import functools

from collections.abc import Iterable

__all__ = []
def export(fn):
    __all__.append(fn.__name__)
    return fn

@export
class Registrar(dict):
    def __init__(self):
        super().__init__()
        self._default = None

    def __getitem__(self, key):
        if self._default and key not in self: return self._default
        else: return super().__getitem__(key)

    def register(self, *args, **kwargs):
        if len(args) == 1:
            if callable(args[0]):
                fn = args[0]
                self[fn.__name__] = fn
                return fn

            name = args[0]
        elif len(args) == 0 and 'name' in kwargs: name = kwargs['name']
        else: name = None

        default = kwargs.get('default', False)
        if name is None and not default: raise TypeError('Invalid argument(s)!')

        def register_name(fn):
            if name is not None: self[name] = fn
            if default: self._default = fn
            return fn

        return register_name

    def dispatch(self, name, *args, **kwargs):
        return (self[name])(*args, **kwargs)

@export
def ifnone(obj, default):
    return obj if obj is not None else default

@export
def defattr(obj, name, value):
    if not hasattr(obj, name):
        setattr(obj, name, value)
        return True
    return False

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
def anyin(obj, iterable):
    return any(map(functools.partial(operator.contains, obj), iterable))

@export
def allin(obj, iterable):
    return all(map(functools.partial(operator.contains, obj), iterable))

@export
def countin(obj, iterable):
    n, f = 0, filter(functools.partial(operator.contains, obj), iterable)
    for _ in f: n += 1
    return n

@export
def gein(obj, count, iterable):
    n, f = 0, filter(functools.partial(operator.contains, obj), iterable)
    for _ in f:
        n += 1
        # early exit
        if n >= count: return True

    return False

@export
def gtin(obj, count, iterable):
    return gein(obj, count+1, iterable)

@export
def multiplein(obj, iterable):
    return gein(obj, 2, iterable)

@export
def eprint(*args, **kwargs):
    if kwargs.pop('file', None):
        raise TypeError('Keyword argument `file` must be omited or `None`!')
    print(*args, file=sys.stderr, **kwargs)
