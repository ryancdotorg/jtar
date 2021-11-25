#!/usr/bin/env python3

import sys
import json
import codecs

class ConcatonatedJSONDecodeError(json.JSONDecodeError):
    def __init__(self, msg, pos):
        errmsg = '%s: char %d' % (msg, pos)
        ValueError.__init__(self, errmsg)
        self.msg = msg
        self.pos = pos
        self.doc = None
        self.lineno = None
        self.colno = None

    def __reduce__(self):
        return self.__class__, (self.msg, self.pos)

# internal helper class
class ConcatonatedJSONDecoder:
    def __init__(self, decoder, *, separators = {'\n', '\r'}, **kwargs):
        self._decoder = decoder or json.JSONDecoder(**kwargs)
        self._separators = separators
        self._buffer = ''
        self._offset = 0

    def _advance(self, n):
        self._buffer = self._buffer[n:]
        self._offset += n

    def generate(self, s=''):
        self._buffer += s
        while len(self._buffer):
            if self._buffer[0] in self._separators:
                self._advance(1)
                continue

            try:
                (o, c) = self._decoder.raw_decode(self._buffer)
            except json.JSONDecodeError as e:
                raise ConcatonatedJSONDecodeError(e.msg, e.pos + self._offset)
            self._advance(c)
            yield o

    def __len__(self):
        return len(self._buffer)

def load(fp, *, cls=None, encoding='utf-8', errors='strict', chunk_size=(1<<16), **kwargs):
    decoder = cls(**kwargs) if cls else json.JSONDecoder(**kwargs)
    chunk_size = max(4, chunk_size)
    incr = ConcatonatedJSONDecoder(decoder)

    # we're using raw_decode which requires strings, so wrap binary files
    if isinstance(fp.read(0), bytes):
        fp = codecs.getreader(encoding)(fp, errors)

    saved_error = None
    for chunk in iter(lambda: fp.read(chunk_size), ''):
        try:
            yield from incr.generate(chunk)
            saved_error = None
        except json.JSONDecodeError as e:
            saved_error = e
            # XXX TODO: try to detect conditions that can't be recovered from

    if saved_error:
        raise saved_error

def loads(s, *, cls=None, encoding='utf-8', errors='strict', **kwargs):
    decoder = cls(**kwargs) if cls else json.JSONDecoder(**kwargs)
    if isinstance(s, (bytes, bytearray)):
        s = s.decode(encoding, errors)

    yield from ConcatonatedJSONDecoder(decoder).generate(s)
