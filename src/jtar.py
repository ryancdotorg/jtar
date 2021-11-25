#!/usr/bin/env python3

import io
import re
import sys
import tarfile
import subprocess

from pathlib import Path

from os import fdopen, stat, getenv, getcwd, path, chdir
from base64 import b64decode as b64d
from functools import partial
from itertools import chain

import concatjson

jinja2 = None

EXPN1 = re.compile(r'(?<!\\)\$\{(\w+)\}')
EXPN2 = re.compile(r'(?<!\\)\\\$')

# mostly just a dict wrapper
class _Attr:
    def __init__(self, attr, define=None):
        for k in ('source', 'name'):
            if k in attr: attr[f'_{k}'] = attr.pop(k)
        self.__dict__ = attr
        self._stat = None
        self._define = define

    def _expand(self, s):
        # expand placeholders in the format of ${varible_name}
        s = EXPN1.sub(lambda m: self._define.get(m.group(1)), s)
        # unescape any $ characters
        return EXPN2.sub('$', s)

    # needed to make the `in` operator work
    def __contains__(self, item): return hasattr(self, item)

    def __getattr__(self, attrib):
        if attrib == 'stat':
            if self.source.startswith('base64:'): return None
            if self._stat is None: self._stat = stat(self.source)
            return self._stat
        # only if _name is missing
        elif attrib == '_name':
            return self._source
        elif attrib == 'name':
            return self._expand(self._name)
        elif attrib == 'source':
            return self._expand(self._source)
        elif attrib == 'atime':
            if self.stat: return self.stat.st_atime
        elif attrib == 'ctime':
            if self.stat: return self.stat.st_ctime
        elif attrib in ('template', 'recursive'):
            return False
        else:
            # this makes e.g. `attr.get(...)` work
            return getattr(self.__dict__, attrib)

class TarBuilder(tarfile.TarFile):
    def __init__(self, name=None, mode='r', fileobj=None, **kwargs):
        super().__init__(name, mode, fileobj, **kwargs)

# apply attributes
def modify(attr, info):
    info.mode = int(str(attr.mode), 8) if 'mode' in attr else attr.stat.st_mode

    if 'mtime' in attr:
        info.mtime = attr.stat.st_mtime if attr.mtime == 'stat' else attr.mtime

    if 'linkname' in attr:
        info.linkname = attr.linkname

    if 'uid' in attr:
        info.uid = attr.stat.st_uid if attr.uid == 'stat' else attr.uid

    if 'gid' in attr:
        info.gid = attr.stat.st_gid if attr.gid == 'stat' else attr.gid

    if 'uname' in attr:
        # setting null in json will omit
        info.uname = '' if attr.uname is None else attr.uname

    if 'gname' in attr:
        # setting null in json will omit
        info.gname = '' if attr.gname is None else attr.gname

    if 'atime' in attr:
        if attr.atime == 'stat':
            info.pax_headers['atime'] = str(attr.stat.st_atime)
        else:
            info.pax_headers['atime'] = str(float(attr.atime))

    if 'ctime' in attr:
        if attr.ctime == 'stat':
            info.pax_headers['ctime'] = str(attr.stat.st_ctime)
        else:
            info.pax_headers['ctime'] = str(float(attr.ctime))

    if 'exclude' in attr:
        if re.fullmatch(attr.exclude, info.name):
            return None

    return info

def cmd_filter(args, data):
    if not isinstance(args, list):
        raise ValueError("Filter must be an argument list or list of lists!")

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

    return cmd_filter(args, out) if len(args) else out

def tar_add(tar, attr, define, env):
    src, dst, f = attr.source, attr.name, None

    if src.startswith('base64:'):
        if attr.recursive:
            raise ValueError("Can't recurse for base64 source!")
        f = io.BytesIO(b64d(src[7:]))

    if attr.template:
        if attr.recursive:
            raise ValueError("Can't recurse for templated source!")
        template = env.get_template(src)
        f = io.BytesIO(template.render(define).encode())

    if 'filter' in attr:
        if attr.recursive:
            raise ValueError("Can't recurse for filtered source!")

        if f is None:
            f = open(src, 'rb')

        f = cmd_filter(attr.filter, f)

    if f is None:
        tar.add(src, dst, attr.recursive, filter=partial(modify, attr))
    else:
        info = tarfile.TarInfo(dst)
        f.seek(0, 2)
        info.size = f.tell()
        f.seek(0, 0)
        info = modify(attr, info)
        tar.addfile(info, f)
        f.close()

def tar_items(out, items, *, directory=None, define={}, compress='', format=tarfile.PAX_FORMAT, **kwargs):
    kwargs['format'] = format

    # set up output mode and and compression options
    if isinstance(out, io.IOBase) or callable(getattr(out, 'write', None)):
        kwargs['fileobj'] = out
        if getattr(out, 'seekable', lambda: False)():
            kwargs['mode'] = 'w:' + compress
        else:
            kwargs['mode'] = 'w|' + compress
    else:
        kwargs['name'] = out
        kwargs['mode'] = 'w:' + compress

    #with tarfile.open(**kwargs) as tar:
    with TarBuilder.open(**kwargs) as tar:
        if directory:
            chdir(directory)
        env = None
        for item in items:
            # handle both individual items and lists of items
            if not isinstance(item, list): item = [item]
            for attr in map(lambda x: _Attr(x, define), item):
                if attr.template and env is None:
                    global jinja2
                    if not jinja2: import jinja2
                    env = jinja2.Environment(
                        loader=jinja2.FileSystemLoader(getcwd(), followlinks=True),
                        autoescape=False, keep_trailing_newline=True,
                    )
                    if define:
                        for k in define:
                            env.globals[k] = define[k]

                tar_add(tar, attr, define, env)

def create_tar(args):
    if args.compress is None:
        if args.outfile and isinstance(args.outfile.name, str):
            suffix = Path(args.outfile.name).suffix
            if suffix in  ('.gz', '.tgz', '.taz'):
                args.compress = 'gz'
            elif suffix in ('.bz2', '.tbz', '.tbz2', '.tz2'):
                args.compress = 'bz2'
            elif suffix in ('.xz', '.txz'):
                args.compress = 'xz'
        else:
            args.compress = ''

    loaders = map(concatjson.load, args.infiles)
    tar_items(
        args.outfile, chain(*loaders),
        directory=args.directory,
        compress=args.compress,
        define=args.define or {},
    )

def create_manifest(args):
    import json

    for fd in args.infiles:
        #with tarfile.open(fileobj=fd.buffer) as tar:
        with TarBuilder.open(fileobj=fd.buffer) as tar:
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
        '-C', '--directory', dest='directory', type=DirectoryType, metavar='DIR',
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
