#!/usr/bin/env python3

import re, os, stat, functools

from stat import *
from operator import or_
from functools import reduce

__all__ = ['chmod', 'vchmod', 'schmod', 'fchmod', 'lchmod']

_WHO = {'u': 'USR', 'g': 'GRP', 'o': 'OTH'}
_MOD = re.compile(r'''
    (?P<type>[FD])?                 # `F` or `D` for type
    (?: (?P<op1>[+=-]?)             # operation
        (?P<oct1>0*[0-7]{3,4})      # octal mode
    |   (?P<who>[augo]*)            # `a` or permutations of `u`, `g`, and `o`
        (?P<op2>[+=-])              # operation
        (?: (?P<ref>[ugo])          # reference other set
        |   (?P<sym>[rwxXts]*)      # symbolic mode
        |   (?P<oct2>0*[0-7]{3,4})  # octal mode
        )
    )\Z                             # end of string
''', re.VERBOSE)

def or_all(fn, items):
    return reduce(or_, map(fn, items))

# @functools.cache is only in Python 3.9+, so provide fall back to lru_cache
def memoize(fn):
    decorator = getattr(functools, 'cache', functools.lru_cache(maxsize=None))
    return decorator(fn)

def bits(who, perm, type_=None):
    if who in ('a', ''): who = 'ugo'
    if len(who) > 1: return or_all(lambda w: bits(w, perm, type_), who)
    if len(perm) > 1: return or_all(lambda p: bits(who, p, type_), perm)

    if perm == '':
        return 0
    elif perm == 'X':
        return getattr(stat, f'S_IX{_WHO[who]}') if type_ == 'D' else 0
    elif perm == 's':
        if who == 'u': return S_ISUID
        elif who == 'g': return S_ISGID
        else: return 0
    elif perm == 't':
        return S_ISVTX if who == 'o' else 0
    elif perm == '*': return getattr(stat, f'S_IRWX{who.upper()}')
    else: return getattr(stat, f'S_I{perm.upper()}{_WHO[who]}')

def bits_and_or(type_, who, op, octal, sym):
    bits_and, bits_or = 0o7777, 0o0
    if octal:
        bits = int(octal, 8)
        if op is None:
            # chmod preserves suid/sgid on directories unless there 5+ digits
            if len(octal) < 5 and type_ == 'D':
                bits_and = S_ISUID | S_ISGID
            else:
                bits_and = 0o0
            bits_or = bits
        elif op == '=':
            bits_and = bits
        elif op == '+':
            bits_or = bits
        elif op == '-':
            bits_and = 0o7777 ^ bits
    else:
        bits = bits(who, sym, type_)
        if op == '=':
            bits_and = 0o777 ^ bits(who, '*')
            if type_ == 'D': bits_and |= S_ISUID | S_ISGID
            bits_or = bits
        elif op == '+':
            bits_or = bits
        elif op == '-':
            bits_and = 0o7777 ^ bits

    return bits_and, bits_or

def chbits(file_and, dir_and, file_or, dir_or):
    def update(mode, isdir):
        if isdir: return (mode & dir_and) | dir_or
        return (mode & file_and) | file_or

    return update

def chref(src, dst):
    src_mask, dst_mask = bits(src, '*'), 0o7777 ^ bits(dst, '*')
    src_p, dst_p = bits(src, 'x').bit_length(), bits(dst, 'x').bit_length()
    sw = dst_p - src_p
    if src_p > dst_p:
        shift = src_p - dst_p
        def update(mode, isdir):
            mode &= dst_mask
            mode |= (mode & src_mask) >> shift
            return mode
    elif src_p < dst_p:
        shift = dst_p - src_p
        def update(mode, isdir):
            mode &= dst_mask
            mode |= (mode & src_mask) << shift
            return mode
    else:
        def update(mode, isdir):
            return mode

    return update

@memoize
def parse(mode):
    changes, n = [], 0

    for s in mode.split(','):
        if n == 0:
            # (re)set bitmasks
            file_and, dir_and, file_or, dir_or = 0o7777, 0o7777, 0o0, 0o0

        # try to break down a mode updating directive
        m = _MOD.match(s)
        if m:
            type_, who = m.group('type'), m.group('who')
            sym, ref = m.group('sym'), m.group('ref')
            op = m.group('op1') or m.group('op2')
            octal = m.group('oct1') or m.group('oct2')

            if ref is not None:
                # generate and push a mode updater from bitmasks, queue reset
                if n > 0:
                    changes.append(chbits(file_and, dir_and, file_or, dir_or))
                    n = 0
                # generate and push mode updaters from reference
                for c in who: changes.append(chref(ref, c))
            else:
                n += 1
                if type_ != 'D':
                    bits_and, bits_or = bits_and_or('F', who, op, octal, sym)
                    #print(f'F&{bits_and:04o}')
                    #print(f'F|{bits_or:04o}')
                    file_and &= bits_and
                    file_or = (file_or & bits_and) | bits_or
                if type_ != 'F':
                    bits_and, bits_or = bits_and_or('D', who, op, octal, sym)
                    #print(f'D&{bits_and:04o}')
                    #print(f'D|{bits_or:04o}')
                    dir_and &= bits_and
                    dir_or = (dir_or & bits_and) | bits_or
        else:
            raise ValueError(f'invalid mode: `{mode}`')

    # generate and push a mode updater from bitmasks if needed
    if n > 0: changes.append(chbits(file_and, dir_and, file_or, dir_or))

    if len(changes) == 1:
        update = changes[0]
    else:
        def update(mode, isdir):
            for change in changes: mode = change(mode, isdir)
            return mode

    return memoize(update)

def stat_result(stat, **kwargs):
    basic = (
        kwargs.get('st_mode',  stat[0]),
        kwargs.get('st_ino',   stat[1]),
        kwargs.get('st_dev',   stat[2]),
        kwargs.get('st_nlink', stat[3]),
        kwargs.get('st_uid',   stat[4]),
        kwargs.get('st_gid',   stat[5]),
        kwargs.get('st_size',  stat[6]),
        int(kwargs.get('st_atime', stat[7])),
        int(kwargs.get('st_mtime', stat[8])),
        int(kwargs.get('st_ctime', stat[9])),
    )
    extra = stat.__reduce__()[1][1]
    for k, v in kwargs.items(): extra[k] = v
    return os.stat_result(basic, extra)

@memoize
def _vchmod(perm, mode, isdir):
    update = parse(mode)
    return update(perm, isdir)

def vchmod(perm, mode, isdir=None):
    if isinstance(perm, int):
        if isdir is None:
            raise TypeError("isdir can't be `None` if perm is an int")
    elif isinstance(perm, os.stat_result):
        if isdir is not None:
            raise TypeError('isdir must be `None` if perm is a stat_result')
        perm, isdir = S_IMODE(perm.st_mode), S_ISDIR(perm.st_mode)
    else:
        raise TypeError(f'perm is invalid type `{type(perm)}`')

    return _vchmod(perm, mode, isdir)

def schmod(st, mode):
    # get basic atrributes in a modifiable form
    l = list(perm)
    # update st_mode
    l[0] = S_IFMT(l[0]) | _vchmod(S_IMODE(l[0]), mode, S_ISDIR(l[0]))
    # get extra attributes
    d = {k: getattr(st, k) for k in dir(st) if k.startswith('st_')}
    return os.stat_result(l, d)

def chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
    st = os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
    mode = S_IMODE(schmod(st, mode).st_mode)
    return os.chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

def fchmod(fd, mode):
    st = os.fstat(fd)
    mode = vchmod(st, mode)
    return os.fchmod(fd, mode)

def lchmod(path, mode):
    return chmod(path, mode, follow_symlinks=False)

if __name__ == '__main__':
    import sys
    orig = int(sys.argv[1], 8)
    newf = vchmod(orig, sys.argv[2], False)
    newd = vchmod(orig, sys.argv[2], True)
    print(f'F:{orig:04o} -> {newf:04o}')
    print(f'D:{orig:04o} -> {newd:04o}')
