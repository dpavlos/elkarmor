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


class ELKProxyAppInternalException(Exception):
    pass


class RequestedAsterisk(ELKProxyAppInternalException):
    pass


class InvalidAPICall(ELKProxyAppInternalException):
    pass


class InvalidJSON(ELKProxyAppInternalException):
    pass


def requested_indices(iterable):
    """
    Yield only indices which don't start with a `-', without a leading `+'
    """

    for idx in iterable:
        if not idx.startswith('-'):
            yield idx[1:] if idx.startswith('+') else idx


def parse_json(s):
    try:
        return json.loads(s)
    except ValueError:
        raise InvalidJSON(s)


json_types = (('object', dict),)


def assert_json_type(j, t):
    for (s, json_type) in json_types:
        if issubclass(t, json_type):
            if not isinstance(j, json_type):
                raise InvalidAPICall('not a JSON {0}: {1}'.format(s, json.dumps(j)))
            return j


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

    api = req_idxs = defidx = None
    idx_given = False
    if not passthrough:
        # Determine API and requested indices

        for path_part in ifilter_bool(path_info[1:].split('/')):
            underscore = path_part.startswith('_')
            if req_idxs is None:
                req_idxs = not underscore and path_part
            if underscore and path_part != '_all':
                api = path_part[1:]
                break

        mget_bulk = (api or '') in ('mget', 'bulk')
        if req_idxs:
            req_idxs = frozenset((req_idxs,) if mget_bulk else itertools.imap(
                normalize_pattern, ifilter_bool(requested_indices(req_idxs.split(',')))
            ))

        if req_idxs:
            idx_given = True
            if mget_bulk:
                defidx = tuple(req_idxs)[0]
        else:
            req_idxs = frozenset('*')

        # Collect allowed indices

        allow_idxs = frozenset(itertools.chain.from_iterable(
            elkenv['restrictions']['users'].get(user, {}).itervalues()
        ))

        if not mget_bulk:
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
            try:
                sio = StringIO(body)
                try:
                    body_json = tuple(itertools.imap(
                        (lambda x: assert_json_type(parse_json(x), dict)),
                        itertools.imap(
                            (lambda x: x or '{}'),
                            istrip((l for (l, b) in itertools.izip(sio, itertools.cycle((True, False))) if b))
                        ) if api == 'msearch' else istrip(sio)
                    ))
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
                                    for idx in idxs:
                                        if not isinstance(idx, str):
                                            raise InvalidAPICall('invalid index: {0} (must be a string)'.format(
                                                json.dumps(idx)
                                            ))
                                else:
                                    raise InvalidAPICall(
                                        'invalid indices: {0} (must be an array or a string)'.format(
                                            json.dumps(idxs)
                                        )
                                    )

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
                else:  # api == 'bulk'
                    actions = ('index', 'create', 'delete', 'update')
                    actions_source = ('index', 'create')
                    body_idxs = set()
                    skip = False

                    for j in body_json:
                        if skip:
                            skip = False
                            continue

                        l = len(j)
                        if l != 1:
                            raise InvalidAPICall(
                                'invalid operation: {0} (must contain exactly one action -- {1} given)'.format(
                                    json.dumps(j), l
                                )
                            )

                        action, meta_data = j.items()[0]
                        if action not in actions:
                            raise InvalidAPICall('invalid action: {0} (must be one of the following: {1})'.format(
                                json.dumps(action), ', '.join(actions)
                            ))

                        if not ('_index' in meta_data or idx_given):
                            raise InvalidAPICall('invalid operation: {0} (no index given)'.format(json.dumps(j)))

                        body_idxs.add(meta_data.get('_index', defidx))

                        if action in actions_source:
                            skip = True
            except InvalidAPICall as e:
                m = str(e)
                start_response('422 Unprocessable Entity', [('Content-Type', 'text/plain')])
                return 'Invalid Elasticsearch API call or not analyzable' + (m and ': ' + m),
            except InvalidJSON as e:
                start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                return 'Invalid JSON: ' + repr(str(e)),

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
