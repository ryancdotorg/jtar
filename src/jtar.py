#!/usr/bin/env python3

import io
import os
import re
import sys
import tarfile
import functools
import subprocess

from os import fdopen, stat, getenv, getcwd, path, chdir, SEEK_SET, SEEK_END
from base64 import b64decode as b64d
from collections import namedtuple, OrderedDict
from functools import partial
from itertools import chain
from time import time

# bundled
import concatjson
from chmod import vchmod

# @functools.cache is only in Python 3.9+, so provide fall back
def memoize(fn):
    decorator = getattr(functools, 'cache', functools.lru_cache(maxsize=None))
    return decorator(fn)

# @functools.cached_property is only in Python 3.8+, so provide fall back
def cached_property(fn):
    decorator = getattr(functools, 'cached_property', lambda fn: property(memoize(fn)))
    return decorator(fn)

jinja2 = None

SEP = path.sep
EXPN1 = re.compile(r'(?<!\\)\$\{(\w+)\}')
EXPN2 = re.compile(r'(?<!\\)\\\$')

QueuedInfo = namedtuple('QueuedInfo', ['src', 'is_dir', 'thunk'])

class _Attr:
    def __init__(self, attr, define=None):
        self._attr = attr
        self._stat = None
        self._define = define

    def sub(self, source, name=None):
        attr = self._attr.copy()
        attr['source'] = source
        if name is None: attr.pop('name', None)
        else: attr['name'] = name
        attr.pop('recursive', None)
        return _Attr(attr, self._define)

    def _expand(self, s):
        # expand placeholders in the format of ${varible_name}
        s = EXPN1.sub(lambda m: self._define.get(m.group(1)), s)
        # unescape any $ characters
        return EXPN2.sub('$', s)

    def __repr__(self):
        return self._attr.__repr__()

    # needed to make the `in` operator work
    def __contains__(self, item): return hasattr(self, item)

    def __getattr__(self, name):
        # attributes that are required to be present first
        if name == 'stat':
            if self.source.startswith('base64:'): return None
            if self._stat is None: self._stat = stat(self.source)
            return self._stat

        elif name == 'name':
            name = self._attr.get('name', self._attr['source'])
            return self._expand(name)

        elif name == 'source':
            return self._expand(self._attr['source'])

        # optional attributes
        elif name in self._attr:
            value = self._attr[name]
            if name == 'mode':
                if isinstance(value, int): value = str(value)
                # returns fn(isdir)
                if attr.stat:
                    return partial(vchmod, attr.stat, value)
                return lambda _: int(value, 8)
            elif name in ('atime', 'ctime'):
                if value == 'now':
                    return time()
                elif value == 'stat' and self._stat:
                    return getattr(self._stat, 'st_' + name)
                return float(value)
            elif name in ('uname', 'gname'):
                return '' if value is None else value
            elif value == 'stat' and self._stat:
                if hasattr(self._stat, 'st_' + name):
                    return getattr(self._stat, 'st_' + name)
            elif name == 'mtime' and value == 'now':
                return time()
            return value

        # defaults for keys not present below here
        elif name in ('template', 'recursive'): return False
        elif name in ('filter', 'exclude'): return None

        raise AttributeError(f"'{type(self)}' object has no attribute '{name}'")


class TarBuilder(tarfile.TarFile):
    def __init__(self, *args, chdir=None, define={}, **kwargs):
        super().__init__(*args, **kwargs)
        self.chdir = chdir
        self.define = define
        self.queued = OrderedDict()

    @classmethod
    def open(cls, out=None, *, compress='', chdir=None, define={}, format=tarfile.PAX_FORMAT, **kwargs):
        # clean up arguments
        for kw in ('name', 'mode', 'fileobj'):
            if kw in kwargs:
                raise TypeError(f"open() got an unexpected keyword argument '{kw}'")

        # set up output mode and and compression options
        if isinstance(out, str):
            kwargs['name'] = out
            kwargs['mode'] = 'w:' + compress
        else:
            if getattr(out, 'seekable', lambda: False)():
                kwargs['mode'] = 'w:' + compress
            else:
                kwargs['mode'] = 'w|' + compress

            kwargs['fileobj'] = out

        return super().open(chdir=chdir, define=define, **kwargs)

    @cached_property
    def env(self):
        global jinja2
        if not jinja2: import jinja2
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(getcwd(), followlinks=True),
            autoescape=False, keep_trailing_newline=True,
        )
        for k in self.define:
            env.globals[k] = self.define[k]

        return env

    def queue_thunk(self, attr):
        src, dst, filter, fn = attr.source, attr.name, partial(modify, attr), None
        isdir = False

        if src.startswith('base64:'):
            fn = lambda: io.BytesIO(b64d(src[7:]))
        elif path.isdir(src):
            isdir = True

        if attr.template and not path.islink(src) and path.isfile(src):
            if fn: fn = partial(template, self.env, self.define, filefunc=fn)
            else: fn = partial(template, self.env, self.define, filename=src)

        if attr.filter:
            if fn is not None: fn = partial(open, src, 'rb')
            fn = cmd_filter(attr.filter, fn)

        if fn: thunk = partial(tar_add, filefunc=fn, arcname=dst, filter=filter)
        else: thunk = partial(tar_add, filename=src, arcname=dst, filter=filter)

        self.queue(dst, QueuedInfo(src, isdir, thunk))

    def queue(self, dst, qi):
        if not qi.is_dir or dst not in self.queued:
            self.queued[dst] = qi

    def close(self):
        for item in self.queued.values():
            # the thunk adds the item to the TarFile
            item.thunk(self)

        super().close()

# apply attributes
def modify(attr, info):
    if 'mode' in attr: info.mode = attr.mode(info.isdir())

    for k in ('mtime', 'linktime', 'uid', 'gid', 'uname', 'gname'):
        if hasattr(attr, k): setattr(info, k, getattr(attr, k))

    for k in ('atime', 'ctime'):
        if hasattr(attr, k): info.pax_headers[k] = getattr(attr, k)

    if attr.exclude is not None:
        if re.fullmatch(attr.exclude, info.name):
            return None

    return info

def cmd_filter(args, filefunc):
    if not isinstance(args, list):
        raise ValueError("Filter must be an argument list or list of lists!")

    data = filefunc()

    if len(args) == 0:
        return data
    elif not isinstance(args[0], list):
        args = [args]

    if isinstance(data, io.BufferedIOBase):
        buf = data.read()
        data.close()
    else:
        buf = data

    out = subprocess.check_output(args.pop(0), input=buf)
    if isinstance(data, io.BufferedIOBase):
        out = io.BytesIO(out)

    return cmd_filter(args, lambda: out) if len(args) else out

def template(env, define, *, filename=None, filefunc=None):
    if filename is not None and filefunc is not None:
        raise ValueError('Either `filename` or `filefunc` must be non-None')
    elif filename is not None:
        template = env.get_template(filename)
    elif filefunc is not None:
        template = env.from_string(filefunc().read().decode())
    else: raise RuntimeError('Impossible!')

    return io.BytesIO(template.render(define).encode())

def tar_add(tar, *, filename=None, filefunc=None, arcname=None, filter=None):
    if arcname is None: arcname = filename
    if filename is not None and filefunc is not None:
        raise ValueError('Either `filename` or `filefunc` must be non-None')
    elif filename is not None:
        tar.add(filename, arcname, False, filter=filter)
    elif filefunc is not None:
        with filefunc() as f:
            info = tar.tarinfo(arcname)
            f.seek(0, SEEK_END)
            info.size = f.tell()
            f.seek(0, SEEK_SET)
            info = filter(info)
            tar.addfile(info, f)
    else: raise RuntimeError('Impossible!')

def tar_items(out, items, *, chdir=None, define={}, compress='', format=tarfile.PAX_FORMAT, **kwargs):
    kwargs['format'] = format

    with TarBuilder.open(out, chdir=chdir, define=define, compress=compress, **kwargs) as tar:
        if tar.chdir: chdir(tar.chdir)
        env = None
        for item in items:
            # handle both individual items and lists of items
            if not isinstance(item, list): item = [item]
            for attr in map(lambda x: _Attr(x, define), item):
                if not attr.recursive:
                    tar.queue_thunk(a)
                else:
                    srcbase = attr.source
                    if srcbase != '' and srcbase[-1] != SEP: srcbase += SEP

                    dstbase = attr.name
                    if dstbase != '' and dstbase[-1] != SEP: dstbase += SEP

                    if not path.isdir(srcbase):
                        raise ValueError(f"`recursive` set but `{srcbase}` isn't a directory!")

                    for srcdir, dirnames, filenames in os.walk(srcbase):
                        if srcdir[-1] != SEP: srcdir += SEP
                        dstdir = dstbase + srcdir[len(srcbase):]
                        filenames = chain(dirnames, filenames)
                        for a in map(lambda x: attr.sub(srcdir+x, dstdir+x), filenames):
                            tar.queue_thunk(a)

def create_tar(args):
    if args.compress is None:
        if args.outfile and isinstance(args.outfile.name, str):
            suffix = path.splitext(args.outfile.name)[1]
            if suffix in  ('.gz', '.tgz', '.taz'):
                args.compress = 'gz'
            elif suffix in ('.bz2', '.tbz', '.tbz2', '.tz2'):
                args.compress = 'bz2'
            elif suffix in ('.xz', '.txz'):
                args.compress = 'xz'
            else:
                args.compress = ''
        else:
            args.compress = ''

    loaders = map(concatjson.load, args.infiles)
    tar_items(
        args.outfile, chain(*loaders),
        chdir=args.chdir,
        compress=args.compress,
        define=args.define or {},
    )

def create_manifest(args):
    import json

    for fd in args.infiles:
        with tarfile.open(fileobj=fd.buffer) as tar:
            for info in tar:
                entry = {}
                entry['source'] = info.name
                entry['mtime'] = info.mtime
                entry['uid'] = info.uid
                entry['gid'] = info.gid
                entry['uname'] = info.uname
                entry['gname'] = info.gname
                if info.linkname: entry['linkname'] = info.linkname
                if hasattr(info, 'pax_headers'):
                    pax = info.pax_headers
                    if 'atime' in pax: entry['atime'] = pax['atime']
                    if 'ctime' in pax: entry['ctime'] = pax['ctime']

                args.outfile.write(json.dumps(entry).encode()+b'\n')

def main():
    from argparse import ArgumentParser, ArgumentTypeError, FileType, Action

    class ParseError(Exception):
        pass

    def DirectoryType(d):
        if path.isdir(d): return d
        else: raise ArgumentTypeError(f'{d} is not an accessible directory')

    class DictAction(Action):
        def __init__(self, option_strings, dest, *, sep='=', **kwargs):
            for opt in ('nargs', 'type', 'const', 'choices'):
                if opt in kwargs:
                    raise ValueError(f'Parameter `{opt}` is not allowed!')
            super().__init__(option_strings, dest, **kwargs)
            self.sep = sep

        def __call__(self, parser, namespace, value, option_string=None):
            d = getattr(namespace, self.dest)
            if d is None:
                d = {}
                setattr(namespace, self.dest, d)

            k, _, v = value.partition(self.sep)
            if k in d:
                raise ValueError(f'Multiple dict assignments for key `{k}`!')
            d[k] = v

    parser = ArgumentParser(description='Generate a tar file from a JSON manifest.')

    cargs = parser.add_mutually_exclusive_group()
    cargs.add_argument(
        '--no-auto-compress', dest='compress', action='store_const', const='',
        help='do not automatically compress output file based on suffix',
    )
    cargs.add_argument(
        '-z', dest='compress', action='store_const', const='gz',
        help='compress output with gzip',
    )
    cargs.add_argument(
        '-j', '--bzip2', dest='compress', action='store_const', const='bz2',
        help='compress output with bzip2',
    )
    cargs.add_argument(
        '-J', '--xz', dest='compress', action='store_const', const='xz',
        help='compress output with xz'
    )
    cargs.add_argument(
        '-a', '--auto-compress', dest='compress', action='store_const', const=None,
        help='compress output based on file suffix (default)'
    )
    cargs.add_argument(
        '-g', '--generate', dest='generate', action='store_true',
        help='generate a JSON manifest from tar file'
    )

    parser.add_argument(
        '-T', dest='template', type=FileType('r'), metavar='FILE',
        help='read template definitions from FILE'
    )
    parser.add_argument(
        '-d', '--define', dest='define', action=DictAction, metavar='KEY=VALUE',
        help='define template variable KEY as VALUE'
    )
    parser.add_argument(
        '-C', '--directory', dest='chdir', type=DirectoryType, metavar='DIR',
        help='treat sources as relative to DIR'
    )
    parser.add_argument(
        '-f', dest='outfile', type=FileType('wb'), metavar='FILE',
        help='output filename',
    )
    parser.add_argument(
        'infiles', nargs='*', type=FileType('r'), metavar='FILE',
        help='input filename(s)',
    )

    args = parser.parse_args()

    # parse template definitions
    if args.template:
        import json
        decode = json.JSONDecoder().raw_decode
        # We look for:
        # * zero or more whitespace characters
        # * either:
        #   * a comment
        #   * OR
        #     * any number of word characters
        #     * zero or more spaces
        #     * an '='
        #     * zero or more spaces
        #     * either:
        #       * a quoted string, optionally followed by a comment
        #       * zero or more characters, optionally followed by a comment
        comment = re.compile(r'\s*(?:#.*)?$')
        sep = re.compile(r'\s*(?:(\s*(?:#.*)?)|(\w+)\s*=\s*(?:(".*)|(.*?)\s*(?:#.*)?))$')

        for lineno, line in enumerate(map(lambda x: x.strip(), args.template), 1):
            m = sep.match(line)
            if m is None:
                raise ParseError(f'Invalid syntax: {args.template.name}, line {lineno}')
            _, k, q, v = m.groups()
            if k:
                if q:
                    v, w = decode(q)
                    if not comment.match(q[w:]):
                        raise ParseError(f'Invalid syntax: {args.template.name}, line {lineno}')

                if not args.define: args.define = {}
                # values defined in command line arguments take precedence
                if k not in args.define: args.define[k] = v

    if args.outfile is None:
        args.outfile = fdopen(sys.stdout.fileno(), "wb", closefd=False)

    if len(args.infiles) == 0:
        args.infiles.append(sys.stdin)

    if args.generate: create_manifest(args)
    else: create_tar(args)


if __name__ == '__main__':
    main()
