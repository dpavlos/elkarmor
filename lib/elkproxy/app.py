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


__all__ = ['app']


def app(environ, start_response):
    clen = environ.get('CONTENT_LENGTH', '').strip() or 0
    try:
        clen = int(clen)
        if clen < 0:
            raise ValueError()
    except ValueError:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return 'Invalid Content-Length: ' + repr(clen),

    body = environ['wsgi.input'].read(clen) if clen else ''
    query_str = environ.get('QUERY_STRING', '')
    conn = environ['elkproxy.connector']()

    conn.request(
        environ['REQUEST_METHOD'],
        environ.get('PATH_INFO', '') + (query_str and '?' + query_str),
        body,
        dict(((k[5:].lower().replace('_', '-'), v) for (k, v) in environ.iteritems() if k.startswith('HTTP_')))
    )
    response = conn.getresponse()

    status = response.status
    reason = response.reason
    headers = response.getheaders()
    content = response.read()

    start_response('{0} {1}'.format(status, reason), headers)
    return content,
