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
import json
from base64 import b64decode
from cStringIO import StringIO
from .util import ifilter_bool, istrip, normalize_pattern, SimplePattern


__all__ = ['app']


class RequestedAsterisk(Exception):
    pass


def requested_indices(iterable):
    """
    Yield only indices which don't start with a `-', without a leading `+'
    """

    for idx in iterable:
        if not idx.startswith('-'):
            yield idx[1:] if idx.startswith('+') else idx


http_basic_auth_header = re.compile(r'Basic\s+(\S*)(?!.)', re.I)


def app(environ, start_response):
    elkenv = environ['elkproxy']

    # Deny absolute URLs

    path_info = environ.get('PATH_INFO', '') or '/'
    if not path_info.startswith('/'):
        start_response('403 Forbidden', [('Content-Type', 'text/plain')])
        return "Invalid URL: {0}\nOnly relative ones (starting with `/') are allowed!".format(repr(path_info)),

    query_str = environ.get('QUERY_STRING', '')

    # Collect HTTP headers

    req_headers = dict(((
        k[5:].lower().replace('_', '-'), v
    ) for (k, v) in environ.iteritems() if k.startswith('HTTP_')))

    # Get username

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
    index_patterns = elkenv['index_patterns'].copy()

    api = req_idxs = None
    if not passthrough:
        # Determine API and requested indices

        for path_part in ifilter_bool(path_info[1:].split('/')):
            underscore = path_part.startswith('_')
            if req_idxs is None:
                req_idxs = not underscore and frozenset(itertools.imap(
                    normalize_pattern, ifilter_bool(requested_indices(path_part.split(',')))
                ))
            if underscore and path_part != '_all':
                api = path_part[1:]
                break

        if not req_idxs:
            req_idxs = frozenset('*')

        # Collect allowed indices

        allow_idxs = frozenset(itertools.chain.from_iterable(
            elkenv['restrictions']['users'].get(user, {}).itervalues()
        ))

        # Compare requested indices with allowed ones

        remain_idxs = req_idxs - allow_idxs
        if remain_idxs:
            for idx in remain_idxs - frozenset(index_patterns):
                index_patterns[idx] = SimplePattern(idx)

            allow_patterns = tuple((index_patterns[idx] for idx in allow_idxs))
            for remain_pattern in (index_patterns[idx] for idx in remain_idxs):
                if not any((allow_pattern.superset(remain_pattern) for allow_pattern in allow_patterns)):
                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                    return 'You may not access all requested indices',

    # Get content's length

    clen = environ.get('CONTENT_LENGTH', '').strip() or 0
    try:
        clen = int(clen)
        if clen < 0:
            raise ValueError()
    except ValueError:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return 'Invalid Content-Length: ' + repr(clen),

    # Read request

    body = environ['wsgi.input'].read(clen) if clen else ''

    if not passthrough and (api or '') in ('msearch', 'mget', 'bulk'):
        # Determine indices requested by JSON body

        if api != 'mget':
            body_json = []
            sio = StringIO(body)
            try:
                for l in (itertools.imap((lambda x: x or '{}'), istrip((
                    l for (l, b) in itertools.izip(sio, itertools.cycle((True, False))) if b
                ))) if api == 'msearch' else istrip(sio)):
                    try:
                        j = json.loads(l)
                    except ValueError:
                        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                        return 'Invalid JSON: ' + repr(l),

                    body_json.append(j if isinstance(j, dict) else {})
            finally:
                sio.close()

            if api == 'msearch':
                body_idxs = []
                try:
                    for j in body_json:
                        json_idxs = tuple((j[k] for k in ('index', 'indices') if k in j))
                        if not json_idxs:
                            body_idxs.append(req_idxs)
                            continue

                        line_idxs = frozenset()

                        for idxs in json_idxs:
                            if isinstance(idxs, str):
                                idxs = idxs.split(',')
                            elif isinstance(idxs, list):
                                if not all((isinstance(idx, str) for idx in idxs)):
                                    raise RequestedAsterisk()
                            else:
                                raise RequestedAsterisk()

                            idxs = frozenset(itertools.imap(
                                normalize_pattern, ifilter_bool(requested_indices(idxs))
                            ))
                            if not idxs or idxs & frozenset(('*', '_all')):
                                raise RequestedAsterisk()

                            line_idxs |= idxs

                        body_idxs.append(line_idxs)
                except RequestedAsterisk:
                    body_idxs = frozenset('*')
                else:
                    body_idxs = frozenset(itertools.chain.from_iterable(body_idxs))

    # Forward request

    conn = elkenv['connector']()

    conn.request(
        environ['REQUEST_METHOD'],
        path_info + (query_str and '?' + query_str),
        body,
        req_headers
    )

    # Forward response

    response = conn.getresponse()

    status = response.status
    reason = response.reason
    headers = response.getheaders()
    content = response.read()

    start_response('{0} {1}'.format(status, reason), headers)
    return content,
