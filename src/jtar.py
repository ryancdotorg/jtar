#!/usr/bin/env python3

import io
import re
import sys
import tarfile
import subprocess

from pathlib import Path

from os import fdopen, stat, getenv
from base64 import b64decode as b64d
from functools import partial
from itertools import chain

import concatjson

# mostly just a dict wrapper
class _Attr:
    def __init__(self, attr):
        self.__dict__ = attr
        self._stat = None

    # needed to make the `in` operator work
    def __contains__(self, item):
        return hasattr(self, item)

    def __getattr__(self, attrib):
        if attrib == 'stat':
            if self.source.startswith('base64:'):
                return None
            if self._stat is None:
                self._stat = stat(self.source)

            return self._stat
        elif attrib == 'atime':
            if self.stat:
                return self.stat.st_atime
        elif attrib == 'ctime':
            if self.stat:
                return self.stat.st_ctime
        else:
            # this makes e.g. `attr.get(...)` work
            return getattr(self.__dict__, attrib)

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

def tar_add(tar, attr):
    src, dst, f = attr.source, attr.name, None
    recurse = attr.get('recursive', False)

    if src.startswith('base64:'):
        if recurse:
            raise ValueError("Can't recurse for base64 source!")
        f = io.BytesIO(b64d(src[7:]))

    if 'filter' in attr:
        if recurse:
            raise ValueError("Can't recurse for filtered source!")

        if f is None:
            f = open(src, 'rb')

        f = cmd_filter(attr.filter, f)

    if f is None:
        tar.add(src, dst, recurse, filter=partial(modify, attr))
    else:
        info = tarfile.TarInfo(dst)
        f.seek(0, 2)
        info.size = f.tell()
        f.seek(0, 0)
        info = modify(attr, info)
        tar.addfile(info, f)
        f.close()

def tar_items(out, items, *, compress='', format=tarfile.PAX_FORMAT, **kw):
    kw['format'] = format

    # set up output mode and and compression options
    if isinstance(out, io.IOBase) or callable(getattr(out, 'write', None)):
        kw['fileobj'] = out
        if getattr(out, 'seekable', lambda: False)():
            kw['mode'] = 'w:' + compress
        else:
            kw['mode'] = 'w|' + compress
    else:
        kw['name'] = out
        kw['mode'] = 'w:' + compress

    with tarfile.open(**kw) as tar:
        for item in items:
            # handle both individual items and lists of items
            if not isinstance(item, list):
                item = [item]
            for attr in map(_Attr, item):
                tar_add(tar, attr)

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate a tar file from a JSON manifest.')
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
        '-g', '--generate', dest='generate', action='store_true',
        help='generate a JSON manifest from tar file'
    )
    parser.add_argument(
        '-f', dest='outfile', type=argparse.FileType('wb'), metavar='FILE',
        help='output filename',
    )
    parser.add_argument(
        'infiles', nargs='*', type=argparse.FileType('r'), metavar='FILE',
        help='input filename(s)',
    )

    args = parser.parse_args()

    if args.outfile is None:
        args.outfile = fdopen(sys.stdout.fileno(), "wb", closefd=False)

    if len(args.infiles) == 0:
        args.infiles.append(sys.stdin)

    if args.generate: create_manifest(args)
    else: create_tar(args)

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
    tar_items(args.outfile, chain(*loaders), compress=args.compress)

def create_manifest(args):
    import json

    for fd in args.infiles:
        with tarfile.open(fileobj=fd.buffer) as tar:
            for info in tar:
                entry = {}
                entry['name'] = info.name
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

if __name__ == '__main__':
    main()
