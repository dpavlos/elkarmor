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
from types import NoneType
from libelkproxy import util_json
from .util import ifilter_bool, istrip, normalize_pattern, SimplePattern

from ldap import LDAPError


__all__ = ['app']


class ELKProxyAppInternalException(Exception):
    pass


class RequestedAsterisk(ELKProxyAppInternalException):
    pass


class InvalidAPICall(ELKProxyAppInternalException):
    pass


class InvalidJSON(ELKProxyAppInternalException):
    pass


class AssertJSONTypeFailure(ELKProxyAppInternalException):
    def __init__(self, whole, target, json_types):
        super(AssertJSONTypeFailure, self).__init__()
        self.whole = whole
        self.target = target
        self.json_types = json_types


def requested_indices(iterable):
    """
    Yield only indices which don't start with a `-', without a leading `+'
    """

    for idx in iterable:
        if not idx.startswith('-'):
            yield idx[1:] if idx.startswith('+') else idx


def parse_json(s, *assert_types):
    try:
        j = json.loads(s)
    except ValueError:
        raise InvalidJSON(s)

    w = util_json.ScalarWrapper.wrap_recursive(util_json.unicode_to_str(j))

    if assert_types:
        assert_json_type(w, w, *assert_types)

    return w


json_ts = dict(((json_t, s) for (s, json_ts) in (
    ('object', (dict,)),
    ('array', (list,)),
    ('string', (unicode, str)),
    ('number (int)', (int, long)),
    ('number (real)', (float,)),
    ('boolean', (bool,)),
    ('null', (NoneType,))
) for json_t in json_ts))


def assert_json_type(whole_wrapped, target_wrapped, json_type, *json_types):
    json_types = (json_type,) + json_types
    target = target_wrapped.get_wrapped()

    if isinstance(target, json_types):
        return target

    raise AssertJSONTypeFailure(whole_wrapped, target_wrapped, json_types)


http_basic_auth_header = re.compile(r'Basic\s+(\S*)(?!.)', re.I)


def app(environ, start_response):
    elkenv = environ['elkproxy']
    logger = elkenv['logger']

    try:
        # Deny absolute URLs

        path_info = environ.get('PATH_INFO', '') or '/'
        query_str = environ.get('QUERY_STRING', '')
        url = path_info + (query_str and '?' + query_str)

        if not path_info.startswith('/'):
            logger.info("denying access to URL {0!r} as it doesn't start with a `/'".format(url))
            start_response('403 Forbidden', [('Content-Type', 'text/plain')])
            return "Invalid URL: {0!r}\nOnly relative ones (starting with `/') are allowed!".format(url),

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
                    try:
                        cred = b64decode(b64cred)
                    except TypeError:
                        cred = b64cred
                        raise ValueError('Must be Base64-encoded!')

                    if ':' not in cred:
                        raise ValueError('Must contain a colon (to separate username and password)!')
                except ValueError as e:
                    logger.info(
                        'rejecting non-anonymous request because of'
                        ' malformed authentication credentials: {0!r}'.format(b64cred)
                    )
                    start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                    return 'Invalid authentication credentials: {0!r}\n{1!s}'.format(cred, e),

                user = cred.split(':', 1)[0]

        # Read request

        clen = environ.get('CONTENT_LENGTH', '').strip() or 0
        try:
            clen = int(clen)
            if clen < 0:
                raise ValueError()
        except ValueError:
            logger.info('rejecting request because of malformed content-length: {0!r}'.format(clen))
            start_response('400 Bad Request', [('Content-Type', 'text/plain')])
            return 'Invalid Content-Length: ' + repr(clen),

        body = environ['wsgi.input'].read(clen) if clen else ''

        if not (user is None or user in elkenv['unrestricted']['users'] or any((
            rgx.search(url[1:]) for rgx in frozenset(itertools.chain(
                elkenv['permitted_urls']['users'].get(user, ()), elkenv['unrestricted_urls']
            ))
        ))):
            # Get the user's groups

            ldap_backend = elkenv['ldap_backend']
            try:
                ldap_groups = ldap_backend.get_group_memberships(user)
            except LDAPError as error:
                logger.info('Rejecting non-anonymous request. Reason: ' + error.args[0]['desc'])
                start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                return ()

            if not (ldap_groups & elkenv['unrestricted']['group'] or any((
                rgx.search(url[1:]) for rgx in frozenset((
                    pattern for group in ldap_groups for pattern in elkenv['permitted_urls']['group'].get(group, [])
                ))
            ))):
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

                if ((
                    user in elkenv['read_only_subjects']['users'] or ldap_groups & elkenv['read_only_subjects']['group']
                ) and ((api and api != 'mget') or environ['REQUEST_METHOD'].lower() != 'get')):
                    logger.info(
                        'Rejecting non-anonymous request because {0} has only read access'.format(
                            'either the user {0} or one of their LDAP groups ({1})'.format(
                                user, ', '.join(itertools.imap(repr, ldap_groups)))
                            if ldap_groups else 'the user {0}'.format(user)))
                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                    return ('You are not permitted to perform any other action than GET or _mget',)

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
                            body_json = parse_json(body.strip(), dict)
                            noidx = False

                            for idx in (
                                assert_json_type(body_json, doc, dict).get(
                                    util_json.ScalarWrapper('_index')
                                ) for doc in assert_json_type(
                                    body_json,
                                    body_json.get_wrapped().get(
                                        util_json.ScalarWrapper('docs'), util_json.ScalarWrapper([])
                                    ),
                                    list
                                )
                            ):
                                if idx is None:
                                    noidx = True
                                else:
                                    body_idxs.append(SimplePattern(assert_json_type(body_json, idx, str), literal=True))

                            if not req_idxs and (noidx or assert_json_type(body_json, body_json.get_wrapped().get(
                                util_json.ScalarWrapper('ids'), util_json.ScalarWrapper([])
                            ), list)):
                                raise InvalidAPICall('no index given for some documents to fetch')
                        else:
                            sio = StringIO(body)
                            try:
                                body_json = (parse_json(l, dict) for l in (
                                    (l or '{}' for l in istrip((
                                        l for (l, b) in itertools.izip(sio, itertools.cycle((True, False))) if b
                                    ))) if api == 'msearch' else istrip(sio)
                                ))

                                if api == 'msearch':
                                    try:
                                        for j in body_json:
                                            u = j.get_wrapped()
                                            for idxs in (
                                                assert_json_type(j, u[k], str, unicode, list) for k in itertools.imap(
                                                    util_json.ScalarWrapper, ('index', 'indices')
                                                ) if k in u
                                            ):
                                                idxs = tuple((
                                                    assert_json_type(j, idx, str, unicode) for idx in idxs
                                                )) if isinstance(idxs, list) else idxs.split(',')

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

                                        u = j.get_wrapped()
                                        l = len(u)
                                        if l != 1:
                                            raise InvalidAPICall(
                                                'invalid operation: {0}'
                                                ' (must contain exactly one action -- {1} given)'.format(
                                                    json.dumps(util_json.ScalarWrapper.unwrap_recursive(j)), l
                                                )
                                            )

                                        action, meta_data = u.items()[0]
                                        action = action.get_wrapped()
                                        idx = assert_json_type(j, meta_data, dict).get(
                                            util_json.ScalarWrapper('_index')
                                        )

                                        if action not in actions:
                                            raise InvalidAPICall(
                                                'invalid action: {0} (must be one of the following: {1})'.format(
                                                    json.dumps(action), ', '.join(actions)
                                                )
                                            )

                                        if idx is None:
                                            if not req_idxs:
                                                raise InvalidAPICall(
                                                    'invalid operation: {0} (no index given)'.format(
                                                        json.dumps(util_json.ScalarWrapper.unwrap_recursive(j))
                                                    )
                                                )
                                        else:
                                            body_idxs.append(SimplePattern(
                                                assert_json_type(j, idx, str, unicode), literal=True
                                            ))

                                        if action in actions_source:
                                            skip = True
                            finally:
                                sio.close()
                    except InvalidAPICall as e:
                        m = str(e)
                        logger.info(
                            'rejecting request because of a semantically invalid'
                            ' Elasticsearch API call' + (m and ': ' + m)
                        )
                        start_response('422 Unprocessable Entity', [('Content-Type', 'text/plain')])
                        return 'Semantically invalid Elasticsearch API call' + (m and ': ' + m),
                    except AssertJSONTypeFailure as e:
                        problem = 'unexpected JSON {0}, expected one of: {1}'.format(
                            json_ts[type(e.target.get_wrapped())],
                            ', '.join(frozenset((json_ts[json_t] for json_t in e.json_types)))
                        )
                        jhp = util_json.JSONHighlightPart(e.whole)

                        logger.info(
                            'rejecting request because of a semantically invalid (or not analyzable) '
                            'Elasticsearch API call: {0} {1}'.format(jhp.render_flat(e.target), problem)
                        )
                        start_response('422 Unprocessable Entity', [('Content-Type', 'text/plain')])
                        return 'Semantically invalid Elasticsearch API call or not analyzable:\n{0}\n\n{1}'.format(
                            problem, jhp.render_2d(e.target)
                        ),
                    except InvalidJSON as e:
                        m = repr(str(e))
                        logger.info('rejecting request because of malformed JSON: ' + m)
                        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                        return 'Invalid JSON: ' + m,

                    req_idxs = itertools.chain(req_idxs, body_idxs)

                # Collect allowed indices

                groups = elkenv['restrictions']['group']
                allow_idxs = tuple(SimplePattern.without_subsets(itertools.chain.from_iterable((
                    itertools.chain.from_iterable(perms.itervalues()) for perms in itertools.chain(
                        (elkenv['restrictions']['users'].get(user, {}), elkenv['unrestricted_idxs']),
                        (groups.get(group, {}) for group in ldap_groups)
                    )
                ))))

                # Compare requested indices with allowed ones

                deny_idxs = tuple((req_idx for req_idx in SimplePattern.without_subsets(req_idxs) if not any((
                    allow_idx.superset(req_idx) for allow_idx in allow_idxs
                ))))
                if deny_idxs:
                    deny_idxs = tuple((
                        '{0!r} ({1})'.format(str(idx), 'literal' if idx.literal else 'pattern') for idx in deny_idxs
                    ))

                    logger.info(
                        'rejecting non-anonymous request because {0} access'
                        ' the following requested indices: {1}'.format(
                            'neither the user {0!r} nor their LDAP groups ({1}) may'.format(
                                user, ', '.join(itertools.imap(repr, ldap_groups))
                            ) if ldap_groups else 'the user {0!r} may not'.format(user),
                            ', '.join(deny_idxs)
                        )
                    )
                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                    return 'You may not access the following requested indices:\n ' + '\n '.join(deny_idxs),

        # Forward request

        conn = elkenv['connector']()

        conn.request(
            environ['REQUEST_METHOD'],
            url,
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
