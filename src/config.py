#!/usr/bin/env python3

import re
import json

class ParseError(Exception):
    pass

raw_decode = json.JSONDecoder().raw_decode
comment = re.compile(r'''
    \s*                         # zero or more spaces
    (?:#.*)?                    # optionally, `#` followed by anything
''', re.VERBOSE)
sep = re.compile(rf'''
    \s*                         # zero or more spaces
    (?:                         # begin uncaptured group
        {comment.pattern}       # optional comment (or blank line)
    |                           # OR
        (\w+)                   # a variable name
        \s*=\s*                 # an `=` surrounded by zero or more spaces
        (?:                     # begin uncaptured group
            (".*)               # a `"` followed by any number of characters
        |                       # OR
            (.*?)               # any number of characters (non-greedy group)
            {comment.pattern}   # optional comment
        )                       # end uncaptured group
    )                           # end uncaptured group
    \Z                          # end of string
''', re.VERBOSE)

def _parse_json(fileobj=None):
    return json.load(fileobj)

def _parse_simple(fileobj=None):
    data = {}
    for lineno, line in enumerate(map(lambda x: x.strip(), fileobj), 1):
        m = sep.match(line)
        if m is None:
            raise ParseError(f'Invalid syntax: {fileobj.name}, line {lineno}')
        key, quoted, value = m.groups()
        if key:
            if quoted:
                value, pos = raw_decode(quoted)
                if not com.match(q[pos:]):
                    raise ParseError(f'Invalid syntax: {fileobj.name}, line {lineno}')

            data[key] = value

    return data
