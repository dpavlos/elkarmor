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
import sys
import traceback
from base64 import b64decode
from cStringIO import StringIO
from .util import ifilter_bool, istrip, json_unicode_to_str, normalize_pattern, SimplePattern


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


json_types = (('object', dict), ('array', list), ('string', str))


def assert_json_type(j, t):
    for (s, json_type) in json_types:
        if issubclass(t, json_type):
            if not isinstance(j, json_type):
                raise InvalidAPICall('not a JSON {0}: {1}'.format(s, json.dumps(j)))
            return j


http_basic_auth_header = re.compile(r'Basic\s+(\S*)(?!.)', re.I)


def app(environ, start_response):
    elkenv = environ['elkproxy']
    logger = elkenv['logger']

    try:
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
        ldap_groups = ()
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

                ldap_backend = elkenv['ldap_backend']
                try:
                    ldap_groups = ldap_backend.member_of(user)
                except KeyError:
                    start_response('401 Unauthorized', [('Content-Type', 'text/plain')])
                    return ()

        # Read request

        clen = environ.get('CONTENT_LENGTH', '').strip() or 0
        try:
            clen = int(clen)
            if clen < 0:
                raise ValueError()
        except ValueError:
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return 'Invalid Content-Length: ' + repr(clen),

        body = environ['wsgi.input'].read(clen) if clen else ''

        if not (user is None or user in elkenv['unrestricted']['users']):
            # Determine API and requested indices

            api = ''
            req_idxs = None
            for path_part in ifilter_bool(path_info[1:].split('/')):
                _all = path_part == '_all'
                underscore = path_part.startswith('_')
                if req_idxs is None:
                    req_idxs = (_all or not underscore or ',' in path_part) and path_part
                if underscore and not _all:
                    api = path_part[1:]
                    break

            if req_idxs:
                req_idxs = (
                    SimplePattern(req_idxs, literal=True),
                ) if api in ('mget', 'bulk') else (
                    SimplePattern('*'),
                ) if req_idxs == '_all' else tuple(itertools.imap(
                    SimplePattern, ifilter_bool(requested_indices(req_idxs.split(',')))
                ))

            msearch_mget_bulk = api in ('msearch', 'mget', 'bulk')
            if not req_idxs:
                req_idxs = () if msearch_mget_bulk else (SimplePattern('*'),)

            if msearch_mget_bulk:
                # Determine indices requested by JSON body

                body_idxs = []

                try:
                    if api == 'mget':
                        body_json = json_unicode_to_str(assert_json_type(parse_json(body.strip()), dict))
                        noidx = False

                        for doc in (
                            assert_json_type(doc, dict) for doc in assert_json_type(body_json.get('docs', []), list)
                        ):
                            if '_index' in doc:
                                body_idxs.append(SimplePattern(assert_json_type(doc['_index'], str), literal=True))
                            else:
                                noidx = True

                        if not req_idxs and (noidx or assert_json_type(body_json.get('ids', []), list)):
                            raise InvalidAPICall('no index given for some documents to fetch')
                    else:
                        sio = StringIO(body)
                        try:
                            body_json = (json_unicode_to_str(assert_json_type(parse_json(l), dict)) for l in (
                                (l or '{}' for l in istrip((
                                    l for (l, b) in itertools.izip(sio, itertools.cycle((True, False))) if b
                                ))) if api == 'msearch' else istrip(sio)
                            ))

                            if api == 'msearch':
                                try:
                                    for j in body_json:
                                        for idxs in (j[k] for k in ('index', 'indices') if k in j):
                                            if isinstance(idxs, str):
                                                idxs = idxs.split(',')
                                            elif isinstance(idxs, list):
                                                for idx in idxs:
                                                    if not isinstance(idx, str):
                                                        raise InvalidAPICall(
                                                            'invalid index: {0} (must be a string)'.format(
                                                                json.dumps(idx)
                                                            )
                                                        )
                                            else:
                                                raise InvalidAPICall(
                                                    'invalid indices: {0} (must be an array or a string)'.format(
                                                        json.dumps(idxs)
                                                    )
                                                )

                                            idxs = frozenset(itertools.imap(
                                                normalize_pattern, ifilter_bool(requested_indices(idxs))
                                            ))
                                            if not (idxs or req_idxs) or idxs & frozenset(('*', '_all')):
                                                raise RequestedAsterisk()

                                            body_idxs.extend(itertools.imap(SimplePattern, idxs))
                                except RequestedAsterisk:
                                    body_idxs = (SimplePattern('*'),)
                            else:  # api == 'bulk'
                                actions = ('index', 'create', 'delete', 'update')
                                actions_source = ('index', 'create')
                                skip = False

                                for j in body_json:
                                    if skip:
                                        skip = False
                                        continue

                                    l = len(j)
                                    if l != 1:
                                        raise InvalidAPICall(
                                            'invalid operation: {0}'
                                            ' (must contain exactly one action -- {1} given)'.format(json.dumps(j), l)
                                        )

                                    action, meta_data = j.items()[0]
                                    if action not in actions:
                                        raise InvalidAPICall(
                                            'invalid action: {0} (must be one of the following: {1})'.format(
                                                json.dumps(action), ', '.join(actions)
                                            )
                                        )

                                    if not ('_index' in meta_data or req_idxs):
                                        raise InvalidAPICall(
                                            'invalid operation: {0} (no index given)'.format(json.dumps(j))
                                        )

                                    if '_index' in meta_data:
                                        body_idxs.append(SimplePattern(meta_data['_index'], literal=True))

                                    if action in actions_source:
                                        skip = True
                        finally:
                            sio.close()
                except InvalidAPICall as e:
                    m = str(e)
                    start_response('422 Unprocessable Entity', [('Content-Type', 'text/plain')])
                    return 'Invalid Elasticsearch API call or not analyzable' + (m and ': ' + m),
                except InvalidJSON as e:
                    start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                    return 'Invalid JSON: ' + repr(str(e)),

                req_idxs = itertools.chain(req_idxs, body_idxs)

            # Collect allowed indices

            groups = elkenv['restrictions']['group']
            allow_idxs = tuple(SimplePattern.without_subsets(itertools.chain.from_iterable((
                itertools.chain.from_iterable(perms.itervalues()) for perms in itertools.chain(
                    (elkenv['restrictions']['users'].get(user, {}),),
                    (groups.get(group, {}) for group in ldap_groups)
                )
            ))))

            # Compare requested indices with allowed ones

            if not all((any((
                allow_idx.superset(req_idx) for allow_idx in allow_idxs
            )) for req_idx in SimplePattern.without_subsets(req_idxs))):
                start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                return 'You may not access all requested indices',

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
    except:
        logger.error('an instance of {0} has been thrown while handling a request; traceback: {1}'.format(
            sys.exc_info()[0].__name__,
            repr(traceback.format_exc())
        ))
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return ()
