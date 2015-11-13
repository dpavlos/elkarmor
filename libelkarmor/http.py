# Copyright (C) 2015  NETWAYS GmbH, http://netways.de
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


from socket import AF_INET
from SocketServer import ForkingMixIn
from wsgiref.simple_server import WSGIServer
from ssl import wrap_socket, CERT_NONE


__all__ = ['HTTPServer', 'HTTPSServer']


class ForkingWSGIServer(ForkingMixIn, WSGIServer):
    pass


class HTTPServer(ForkingWSGIServer):
    def __init__(self, *args, **kwargs):
        for (k, d) in (('address_family', AF_INET), ('wsgi_env', {})):
            setattr(self, k, kwargs.pop(k, d))
        WSGIServer.__init__(self, *args, **kwargs)

    def setup_environ(self):
        WSGIServer.setup_environ(self)
        for (k, v) in self.wsgi_env.iteritems():
            self.base_environ[k] = v

    def patch_wsgi_env(self, data, env='elkarmor'):
        for k, v in data.iteritems():
            self.wsgi_env[env][k] = v
            self.base_environ[env][k] = v


class HTTPSServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        self._sslargs = dict(((k, kwargs.pop(k, '') or None) for k in ('keyfile', 'certfile')))
        HTTPServer.__init__(self, *args, **kwargs)

    def get_request(self):
        s, a = HTTPServer.get_request(self)
        return wrap_socket(s, server_side=True, cert_reqs=CERT_NONE, **self._sslargs), a
