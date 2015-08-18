# Copyright (C) 2015  NETWAYS GmbH, http://netways.de
#
# Author: Alexander A. Klimov <alexander.klimov@netways.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import re
import itertools
from base64 import b64decode
from .util import ifilter_bool, SimplePattern


__all__ = ['app']


def requested_indices(iterable):
    for idx in iterable:
        if not idx.startswith('-'):
            yield idx[1:] if idx.startswith('+') else idx


http_basic_auth_header = re.compile(r'Basic\s+(\S*)(?!.)', re.I)


def app(environ, start_response):
    elkenv = environ['elkproxy']

    path_info = environ.get('PATH_INFO', '') or '/'
    if not path_info.startswith('/'):
        start_response('403 Forbidden', [('Content-Type', 'text/plain')])
        return "Invalid URL: {0}\nOnly relative ones (starting with `/') are allowed!".format(repr(path_info)),

    query_str = environ.get('QUERY_STRING', '')

    req_headers = dict(((
        k[5:].lower().replace('_', '-'), v
    ) for (k, v) in environ.iteritems() if k.startswith('HTTP_')))

    user = None
    http_auth_header = req_headers.get('authorization')
    if http_auth_header is not None:
        m = http_basic_auth_header.match(http_auth_header)
        if m is not None:
            b64cred = m.group(1)
            try:
                cred = b64decode(b64cred)
            except TypeError:
                start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                return 'Invalid authentication credentials: {0}\nMust be Base64-encoded!'.format(repr(b64cred)),

            if ':' not in cred:
                start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                return 'Invalid authentication credentials: {0}\n'\
                       'Must contain a colon (to separate username and password)!'.format(repr(cred)),

            user = cred.split(':', 1)[0]

    passthrough = user is None or user in elkenv['unrestricted']['users']
    index_patterns = elkenv['index_patterns']

    if not passthrough:
        req_idxs = frozenset('*')  # TODO: * == _all
        for idxs in ifilter_bool(path_info[1:].split('/')):
            if not idxs.startswith('_'):
                req_idxs = frozenset(ifilter_bool(requested_indices(idxs.split(','))))
            break

        allow_idxs = frozenset(itertools.chain.from_iterable(
            elkenv['restrictions']['users'].get(user, {}).itervalues()
        ))

        req_idxs -= allow_idxs
        if req_idxs:
            req_idxs = tuple(((
                index_patterns[idx] if idx in index_patterns else SimplePattern(idx)
            ) for idx in req_idxs))
            allow_idxs = tuple((index_patterns[idx] for idx in allow_idxs))
            for req_idx in req_idxs:
                for allow_idx in allow_idxs:
                    if allow_idx.superset(req_idx):
                        break
                else:
                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                    return 'You may not access all requested indices',

    clen = environ.get('CONTENT_LENGTH', '').strip() or 0
    try:
        clen = int(clen)
        if clen < 0:
            raise ValueError()
    except ValueError:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return 'Invalid Content-Length: ' + repr(clen),

    body = environ['wsgi.input'].read(clen) if clen else ''
    conn = elkenv['connector']()

    conn.request(
        environ['REQUEST_METHOD'],
        path_info + (query_str and '?' + query_str),
        body,
        req_headers
    )
    response = conn.getresponse()

    status = response.status
    reason = response.reason
    headers = response.getheaders()
    content = response.read()

    start_response('{0} {1}'.format(status, reason), headers)
    return content,
