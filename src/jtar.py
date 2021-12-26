#!/usr/bin/env python3

import re
import sys
import tarfile
import functools
import subprocess

from io import BytesIO, BufferedIOBase
from os import walk, fdopen, stat, path, getcwd, chdir, SEEK_SET, SEEK_END
from collections import namedtuple, OrderedDict, Iterable
from base64 import b64decode as b64d
from functools import partial
from itertools import chain
from time import time

# non-stdlib
try:
    # pip3 install zopfli
    import zopfli
    zopfli.__COMPRESSOR_DOCSTRING__ = getattr(zopfli, '__COMPRESSOR_DOCSTRING__', '')
    from zopfli.gzip import compress
    def zopfli_compress(data, iterations=15):
        return compress(data, numiterations=iterations)
except ImportError as e:
    try:
        # pip3 install pyzopfli
        from zopfli import ZopfliCompressor, ZOPFLI_FORMAT_GZIP
        def zopfli_compress(data, iterations=15):
            c = ZopfliCompressor(ZOPFLI_FORMAT_GZIP, iterations=iterations)
            return c.compress(data) + c.flush()
    except ImportError as e:
        zopfli_compress = None

# bundled
import concatjson
from chmod import vchmod
from util import *

@memoize
def jinja_filters():
    # def filter(value, args...)
    filters = Registrar()

    @filters.register
    def re_sub(string, pattern, repl):
        return re.sub(pattern, repl, string)

    return filters

@memoize
def jinja_functions():
    from random import SystemRandom
    random = SystemRandom()

    functions = Registrar()

    @functions.register
    def randint(a, b, fmt=''):
        n = random.randint(a, b)
        return ('{:'+fmt+'}').format(n)

    return functions

SEP = path.sep
EXPN1 = re.compile(r'(?<!\\)\$\{(\w+)\}')
EXPN2 = re.compile(r'(?<!\\)\\\$')
SPECIALS = ('link', 'fifo', 'block', 'char', 'dir')

QueuedInfo = namedtuple('QueuedInfo', ['src', 'thunk'])

class Entry:
    def __init__(self, entry, define=None):
        if multiplein(entry, SPECIALS):
            raise ValueError('Invalid entry contains multiple special keys')

        self._entry = entry
        self._stat = None
        self._define = define

    def sub(self, source, name=None):
        entry = self._entry.copy()
        entry['source'] = source
        if name is None: entry.pop('name', None)
        else: entry['name'] = name
        entry.pop('recursive', None)
        return Entry(entry, self._define)

    def apply(self, info):
        if hasattr(self, 'block'):
            info.type = tarfile.BLKTYPE
            info.devmajor, info.devminor = self.block
        elif hasattr(self, 'char'):
            info.type = tarfile.CHRTYPE
            info.devmajor, info.devminor = self.char
        elif hasattr(self, 'link'):
            info.type, info.linkname = tarfile.SYMTYPE, self.link
        elif getattr(self, 'fifo', False):
            info.type = tarfile.FIFOTYPE
        elif getattr(self, 'dir', False):
            info.type = tarfile.DIRTYPE

        if hasattr(self, 'mode'):
            info.mode = self.mode()

        for k in ('mtime', 'uid', 'gid', 'uname', 'gname'):
            if hasattr(self, k): setattr(info, k, getattr(self, k))

        for k in ('atime', 'ctime'):
            if hasattr(self, k): info.pax_headers[k] = str(getattr(self, k))

        if self.exclude is not None:
            if re.fullmatch(self.exclude, info.name):
                return None

        return info

    def _expand(self, s):
        # expand placeholders in the format of ${varible_name}
        s = EXPN1.sub(lambda m: self._define.get(m.group(1)), s)
        # unescape any $ characters
        return EXPN2.sub('$', s)

    def __repr__(self):
        return self._entry.__repr__()

    # needed to make the `in` operator work
    def __contains__(self, item): return hasattr(self, item)

    def __getattr__(self, name):
        if name == 'stat':
            # no actual file to stat
            if self.source is None or self.source.startswith('base64:'): return None
            # save data from source file
            if self._stat is None: self._stat = stat(self.source, follow_symlinks=False)
            return self._stat

        # symlink permissions are always 777
        elif name == 'mode' and 'link' in self._entry:
            return lambda: 0o777

        # source is required except for symlinks and specials
        elif name == 'source':
            if anyin(self._entry, SPECIALS):
                if 'source' not in self._entry:
                    return None
            return self._expand(self._entry['source'])

        # name should either be macro expanded or copied from source
        elif name == 'name':
            if 'name' in self._entry: return self._expand(self._entry['name'])
            else: return self.source

        # optional attributes
        elif name in self._entry:
            value = self._entry[name]
            if name == 'mode':
                if isinstance(value, int): value = str(value)
                # returns fn()
                if self.stat: return partial(vchmod, self.stat, value)
                return lambda: int(value, 8)
            elif name in ('atime', 'ctime'):
                if value == 'now':
                    return time()
                elif value == 'stat' and self.stat:
                    return getattr(self.stat, 'st_' + name)
                return float(value)
            elif name in ('uname', 'gname'):
                return '' if value is None else value
            elif value == 'stat' and self.stat:
                if hasattr(self.stat, 'st_' + name):
                    return getattr(self.stat, 'st_' + name)
            elif name == 'mtime' and value == 'now':
                return time()
            return value

        # special cases for root user/group where only one of id/name is specified
        elif name == 'uid' and self._entry.get('uname', None) == 'root': return 0
        elif name == 'gid' and self._entry.get('gname', None) == 'root': return 0
        elif name == 'uname' and self._entry.get('uid', None) == 0: return 'root'
        elif name == 'gname' and self._entry.get('gid', None) == 0: return 'root'

        # defaults for keys not present below here
        elif name in ('template', 'recursive'): return False
        elif name in ('filter', 'exclude'): return None

        # fallback to stat
        elif self.stat:
            if hasattr(self.stat, 'st_' + name):
                if name == 'mode': return lambda *a: self.stat.st_mode
                return getattr(self.stat, 'st_' + name)

        raise AttributeError(f"'{type(self)}' object has no attribute '{name}'")

# convience class to:
# * bind TarInfo instances to the TarFile they're members of
# * provide a directory tree
VIRTTYPE = b"\xfe"
DIRTYPES = (VIRTTYPE, tarfile.DIRTYPE)
class ExtInfo(tarfile.TarInfo):
    def __new__(cls, *args, **kwargs):
        if cls is ExtInfo:
            raise TypeError(f"only subclasses of '{cls.__name__}' may be instantiated")

        return object.__new__(cls)

    def __init__(self, type_=None, children=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if type_ is not None: self.type = type_
        self.children = children if children is not None else {}

    def __getitem__(self, key):
        return self.children[key]

    def _update_tree(self):
        rootname, parts = '', self.name.split('/')

        # setup/update root member
        if self.tar.rootmember is None:
            if self.name == rootname: self.tar.rootmember = self
            else: self.tar.rootmember = self.__class__(name=rootname, type_=VIRTTYPE)
        elif self.name == rootname:
            self.children = self.tar.rootmember.children
            self.tar.rootmember = self

        # find/create our direct parent node
        parent = self.tar.rootmember
        for i, part in enumerate(parts[:-1], 1):
            name = '/'.join(parts[:i])
            if part in parent.children:
                parent = parent.children[part]
                continue

            # generate a virtual directory since one doesn't exist in the tree
            virt = self.__class__(name='/'.join(parts[:i]), type_=VIRTTYPE)
            parent.children[part] = virt
            parent = virt

        # replace existing child if required
        if parts[-1] in parent.children:
            self.children = parent.children[parts[-1]].children

        # add an entry for ourselves
        parent.children[parts[-1]] = self

    @classmethod
    def bind(cls, tar):
        return type(cls.__name__, (cls,), {'tar': tar})

    @classmethod
    def fromtarfile(cls, tarfile):
        info = super().fromtarfile(tarfile)
        info._update_tree()
        return info

    @property
    def files(self):
        if self.type not in DIRTYPES:
            raise TypeError(f'ExtInfo member {self.name} is not a directory!')
        return dict(filter(lambda a: a[1].type not in DIRTYPES, self.children.items()))

    @property
    def filenames(self):
        return self.files.keys()

    @property
    def dirs(self):
        if self.type not in DIRTYPES:
            raise TypeError(f'ExtInfo member {self.name} is not a directory!')
        return dict(filter(lambda a: a[1].type in DIRTYPES, self.children.items()))

    @property
    def dirnames(self):
        return self.dirs.keys()

    def isvirt(self):
        return self.type == VIRTTYPE

    def walk(self):
        # create a copy of dirnames so it can be modified by the caller, see os.walk
        dirnames = list(self.dirnames)
        yield (self.name, dirnames, self.filenames)
        for dirname in dirnames:
            yield from self[dirname].walk()

    def extractfile(self):
        if self.isfile(): return self.tar.extractfile(self)
        else: raise TypeError(f'ExtInfo member {self.name} is not a regular file!')

    def add_to(self, target):
        if self.isfile():
            f = self.extractfile()
            self.tar = target
            target.addfile(self, f)
        else: target.addfile(self)

class TarSource(tarfile.TarFile):
    def __init__(self, *args, **kwargs):
        self.rootmember = None
        super().__init__(tarinfo=ExtInfo.bind(self), *args, **kwargs)

for name in ('add', 'addfile', 'extract', 'extractall'):
    def fn(self, *args, **kwargs):
        raise NotImplementedError(f'TarSource instances do not support `{name}`!')
    setattr(TarSource, name, fn)

class TarBuilder(tarfile.TarFile):
    def __init__(self, *args, chdir=None, dirs='first', define={}, **kwargs):
        super().__init__(*args, **kwargs)
        self.dirs = dirs
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

        kwargs['format'] = format
        return super().open(chdir=chdir, define=define, **kwargs)

    @cached_property
    def env(self):
        try:
            import jinja2
        except ModuleNotFoundError:
            raise ModuleNotFoundError('Install `jinja2` to use templates.')

        env = jinja2.Environment(
            autoescape=False, keep_trailing_newline=True,
            loader=jinja2.FileSystemLoader(getcwd(), followlinks=True),
        )
        for k, v in jinja_filters().items(): env.filters[k] = v
        for k, v in jinja_functions().items(): env.globals[k] = v
        return env

    def _template(self, *, filename=None, filefunc=None):
        if filename is not None and filefunc is not None:
            raise ValueError('Either `filename` or `filefunc` must be non-None')
        elif filename is not None:
            template = self.env.get_template(filename)
        elif filefunc is not None:
            template = self.env.from_string(filefunc().read().decode())
        else: raise RuntimeError('Impossible!')

        return BytesIO(template.render(self.define).encode())

    def _add(self, *, filename=None, filefunc=None, arcname=None, filter=None):
        if arcname is None: arcname = filename
        if filename is not None and filefunc is not None:
            raise ValueError('Either `filename` or `filefunc` must None')
        elif filename is not None:
            self.add(filename, arcname, False, filter=filter)
        elif filefunc is not None:
            with filefunc() as f:
                info = self.tarinfo(arcname)
                f.seek(0, SEEK_END)
                info.size = f.tell()
                f.seek(0, SEEK_SET)
                self.addfile(filter(info), f)
        else:
            info = filter(self.tarinfo(arcname))
            self.addfile(info)

    def addfile(self, tarinfo, fileobj=None):
        if tarinfo.type != VIRTTYPE:
            super().addfile(tarinfo, fileobj)

    def queue(self, entry):
        if isinstance(entry, (self.tarinfo, tarfile.TarInfo)):
            thunk = partial(self.addfile, entry)
            self.queued[entry.name] = QueuedInfo(entry.name, thunk)
            return

        src, dst, filter, fn = entry.source, entry.name, entry.apply, None
        isdir = False

        if src:
            if src.startswith('base64:'):
                fn = lambda: BytesIO(b64d(src[7:]))
            elif path.isdir(src):
                isdir = True

            if path.isfile(src):
                if entry.template:
                    if fn: fn = partial(self._template, filefunc=fn)
                    else: fn = partial(self._template, filename=src)

                if entry.filter:
                    if fn is not None: fn = partial(open, src, 'rb')
                    fn = cmd_filter(entry.filter, fn)

        if fn: thunk = partial(self._add, filefunc=fn, arcname=dst, filter=filter)
        else: thunk = partial(self._add, filename=src, arcname=dst, filter=filter)

        qi = QueuedInfo(src, thunk)

        if isdir:
            if self.dirs == 'first':
                if dst in self.queued: return
            elif self.dirs == 'omit': return
            elif self.dirs == 'last': pass
            else: raise ValueError(f'Invalid dirs value: `{self.dirs}`')

        self.queued[dst] = qi

    def close(self):
        # the thunk adds the item to the TarFile
        for item in self.queued.values(): item.thunk()
        super().close()

# pipe a file through a command
def cmd_filter(args, filefunc):
    if not isinstance(args, list):
        raise ValueError("Filter must be an argument list or list of lists!")

    data = filefunc()

    if len(args) == 0:
        return data
    elif not isinstance(args[0], list):
        args = [args]

    if isinstance(data, BufferedIOBase):
        buf = data.read()
        data.close()
    else:
        buf = data

    out = subprocess.check_output(args.pop(0), input=buf)
    if isinstance(data, BufferedIOBase):
        out = BytesIO(out)

    return cmd_filter(args, lambda: out) if len(args) else out

def tar_entries(out, entries, **kwargs):
    with TarBuilder.open(out, **kwargs) as tar:
        if tar.chdir: chdir(tar.chdir)
        for entry in map(lambda x: Entry(x, tar.define), entries):
            srcbase = entry.source
            if not entry.source or not path.isdir(entry.source) or not entry.recursive:
                tar.queue(entry)
            else:
                if srcbase != '' and srcbase[-1] != SEP: srcbase += SEP

                dstbase = entry.name
                if dstbase != '' and dstbase[-1] != SEP: dstbase += SEP

                for srcdir, dirnames, filenames in walk(srcbase):
                    if srcdir[-1] != SEP: srcdir += SEP
                    dstdir = dstbase + srcdir[len(srcbase):]
                    filenames = chain(dirnames, filenames)
                    for a in map(lambda x: entry.sub(srcdir+x, dstdir+x), filenames):
                        tar.queue(a)

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

    outfile = BytesIO() if args.zopfli else args.outfile
    entries = flatten(map(concatjson.load, args.infiles))
    tar_entries(
        outfile, entries,
        compress=args.compress,
        define=args.define,
        chdir=args.chdir,
        dirs=args.dirs,
    )

    if args.zopfli:
        outfile.flush()
        args.outfile.write(zopfli_compress(outfile.getvalue(), args.zopfli))

    args.outfile.flush()

def create_manifest(args):
    import json

    for fd in args.infiles:
        with tarfile.open(fileobj=fd.buffer) as tar:
            for info in tar:
                entry = {}
                if info.linkname:
                    entry['link'] = info.linkname
                else:
                    entry['source'] = info.name
                entry['mtime'] = info.mtime
                entry['uid'] = info.uid
                entry['gid'] = info.gid
                entry['uname'] = info.uname
                entry['gname'] = info.gname
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
    parser.set_defaults(zopfli=None)

    cargs = parser.add_mutually_exclusive_group()
    cargs.add_argument(
        '-a', '--auto-compress', dest='compress', action='store_const', const=None,
        help='compress output based on file suffix (default)'
    )
    cargs.add_argument(
        '-z', '--gzip', dest='compress', action='store_const', const='gz',
        help='compress output with gzip',
    )
    if zopfli_compress:
        cargs.add_argument(
            '--zopfli', dest='zopfli', type=int, nargs='?', action='append', metavar='ITERS',
            help='compress output with zopfli (optional parameter: iterations)'
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
        '--no-auto-compress', dest='compress', action='store_const', const='',
        help='do not automatically compress output file based on suffix',
    )
    cargs.add_argument(
        '-g', '--generate', dest='generate', action='store_true',
        help='generate a JSON manifest from tar file'
    )

    dargs = parser.add_mutually_exclusive_group()
    dargs.add_argument(
        '--dirs-first', dest='dirs', action='store_const', const='first',
        help='keep first instance of directory (default)'
    )
    dargs.add_argument(
        '--dirs-last', dest='dirs', action='store_const', const='last',
        help='keep last instance of directory'
    )
    dargs.add_argument(
        '--dirs-omit', dest='dirs', action='store_const', const='omit',
        help='omit directories'
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

    parser.set_defaults(dirs='first', define={})

    args = parser.parse_args()

    if args.zopfli:
        args.compress = ''
        args.zopfli = args.zopfli[0] or 15

    if args.outfile is None:
        args.outfile = fdopen(sys.stdout.fileno(), "wb", closefd=False)

    if len(args.infiles) == 0:
        args.infiles.append(sys.stdin)

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

    if args.generate: create_manifest(args)
    else: create_tar(args)


if __name__ == '__main__':
    main()
