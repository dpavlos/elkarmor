#!/usr/bin/env python

# Copyright (C) 2015  NETWAYS GmbH, http://netways.de
#
# Author: Alexander A. Klimov <alexander.klimov@netways.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import sys
import os
import re
import itertools
import logging
from errno import *
from time import sleep
from threading import Thread
from wsgiref.simple_server import make_server
from socket import error as SocketError, getaddrinfo
from ConfigParser import SafeConfigParser as ConfigParser, Error as ConfigParserError
from daemon import UnixDaemon, get_daemon_option_parser
from .util import *
from .logging_handlers import *
from .http import *


DEVNULL = open(os.devnull, 'r+b')

ECFGDIR = 1
ECFGIO = 2
ECFGSYN = 3
ECFGSEM = 4


class ELKProxyInternalError(Exception):
    def __init__(self, errno, *args):
        self.errno = (errno,) + args
        super(ELKProxyInternalError, self).__init__()


def app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return repr(environ),


class ELKProxyDaemon(UnixDaemon):
    name = 'ELK Proxy'

    def __init__(self, *args, **kwargs):
        self._cfgdir = kwargs.pop('cfgdir')
        self._cfg = {}
        self._servers = []
        self._threads = []
        super(ELKProxyDaemon, self).__init__(*args, **kwargs)

    def before_daemonize(self):
        # Check whether the config directory is present and accessible

        if not os.access(self._cfgdir, os.R_OK | os.X_OK):
            raise ELKProxyInternalError(ECFGDIR)

        # Check whether all required config files are present and (syntactically) valid

        cfg = {}
        for cfn in ('config', 'restrictions'):
            cfp = os.path.join(self._cfgdir, '{0}.ini'.format(cfn))
            try:
                cf = open(cfp, 'r')
            except IOError as e:
                if cfn == 'restrictions' and e.errno == ENOENT:
                    cfg[cfn] = {}
                    continue
                raise ELKProxyInternalError(ECFGIO, e.errno, cfp)

            cfgParser = ConfigParser()
            with cf as cf:
                try:
                    cfgParser.readfp(cf)
                except ConfigParserError as e:
                    raise ELKProxyInternalError(ECFGSYN, e, cfp)

            cfg[cfn] = dict(((section, dict(cfgParser.items(section, True))) for section in cfgParser.sections()))

        self._restrictions = cfg['restrictions']

        # Validate configuration

        ## Network I/O

        netio = cfg['config'].pop('netio', {})

        ### Check for non-empty Elasticsearch URL

        elsrchURL = netio.pop('elasticsearch', '').strip()
        if not elsrchURL:
            raise ELKProxyInternalError(ECFGSEM, 'net-elsrch')

        self._elsrchURL = elsrchURL

        ### SSL-specific options

        self._sslargs = dict(((k, netio.pop(k, '') or None) for k in ('keyfile', 'certfile')))


        if not netio:
            raise ELKProxyInternalError(ECFGSEM, 'net-listen')

        ### Validate addresses and interfaces

        rAddr = re.compile(r'(.+):(\d+)(?!.)')
        rAddr6 = re.compile(r'\[(.+)\](?!.)')
        resolve = getifaddrs()

        listen = {}
        for (afs, af) in (('', AF_INET), ('6', AF_INET6)):
            listen[af] = {}
            for SSL in ('', '-ssl'):
                for addr in ifilter_bool(istrip(parse_split(netio.pop('inet{0}{1}'.format(afs, SSL), ''), ','))):
                    m = rAddr.match(addr)
                    if not m:
                        raise ELKProxyInternalError(ECFGSEM, 'net-fmt', addr)

                    ip, port = m.groups()
                    port = int(port)
                    if port > 65535:
                        raise ELKProxyInternalError(ECFGSEM, 'net-port', port, addr)

                    allowIP = allowIFace = True
                    if af == AF_INET6:
                        m = rAddr6.match(ip)
                        if m:
                            ip = m.group(1)
                            allowIFace = False
                        else:
                            allowIP = False

                    if allowIFace and ip in resolve:
                        if af not in resolve[ip]:
                            raise ELKProxyInternalError(ECFGSEM, 'net-af', af, ip)

                        ip = resolve[ip][af]
                    elif allowIP:
                        try:
                            ip = normalize_ip(af, ip)
                        except ValueError:
                            raise ELKProxyInternalError(ECFGSEM, 'net-ip', af, ip)
                    else:
                        raise ELKProxyInternalError(ECFGSEM, 'net-iface', ip)

                    nAddr = (ip, port)
                    if nAddr in listen[af]:
                        raise ELKProxyInternalError(ECFGSEM, 'net-alrdy', addr)

                    listen[af][nAddr] = bool(SSL)
            if not listen[af]:
                del listen[af]

        if not listen:
            raise ELKProxyInternalError(ECFGSEM, 'net-listen')

        if any((SSL for af in listen.itervalues() for SSL in af.itervalues())) and not any(self._sslargs.itervalues()):
            raise ELKProxyInternalError(ECFGSEM, 'net-ssl')

        self._listen = listen

        ## LDAP

        ldap = cfg['config'].pop('ldap', {})

        ### Host

        host = ldap.pop('host', '').strip() or 'localhost'

        for af in (AF_INET6, AF_INET):
            try:
                host = normalize_ip(af, host)
            except ValueError:
                continue
            break
        else:
            try:
                getaddrinfo(host, None)
            except SocketError:
                raise ELKProxyInternalError(ECFGSEM, 'ldap-host', host)

        ### SSL

        SSL = ldap.pop('ssl', '').strip() or 'off'

        try:
            SSL = {'off': False, 'on': True, 'starttls': 'starttls'}[SSL]
        except KeyError:
            raise ELKProxyInternalError(ECFGSEM, 'ldap-ssl', SSL)

        ### Port

        port = ldap.pop('port', '').strip() or (636 if SSL is True else 389)

        try:
            port = int(port)
        except ValueError:
            raise ELKProxyInternalError(ECFGSEM, 'ldap-port', port)

        if port > 65535:
            raise ELKProxyInternalError(ECFGSEM, 'ldap-port', port)

        ### Username, password and root DN

        self._ldap = dict(itertools.chain(
            (('host', host), ('port', port), ('ssl', SSL)),
            ((k, (str if k == 'pass' else str.strip)(ldap.pop(k, ''))) for k in ('user', 'pass', 'rootdn'))
        ))

        ## Logging

        log = cfg['config'].pop('log', {})

        logLvl = {
            'crit':     logging.CRITICAL,
            'err':      logging.ERROR,
            'warn':     logging.WARNING,
            'info':     logging.INFO,
            'debug':    logging.DEBUG
        }
        logging_cfg = {}
        for (k, opts) in (('type', ('file', 'syslog')), ('level', tuple(logLvl))):
            v = log.pop(k, '').strip()
            if v not in opts:
                raise ELKProxyInternalError(ECFGSEM, 'log-opt', k, v, opts)

            logging_cfg[k] = v

        if logging_cfg['type'] == 'file':
            fpath = log.pop('path', '')
            if not fpath:
                raise ELKProxyInternalError(ECFGSEM, 'log-path')

            try:
                logHandler = FileHandler(fpath)
            except IOError as e:
                raise ELKProxyInternalError(ECFGSEM, 'log-io', fpath, e.errno)
        else:
            logHandler = SysLogHandler(log.pop('prefix', '').strip() or 'elkproxyd')

        # Set up logging

        log = logging.getLogger()
        log.addHandler(logHandler)
        log.setLevel(logLvl[logging_cfg['level']])

        daemonLogger = logging.getLogger('daemon')
        for handler in daemonLogger.handlers:
            daemonLogger.removeHandler(handler)

        self._log = log

    def cleanup(self):
        for s in self._servers:
            s.shutdown()
        for t in self._threads:
            t.join()
        logging.shutdown()
        super(ELKProxyDaemon, self).cleanup()

    def run(self):
        def server_wrapper(address_family, SSL):
            return lambda *args, **kwargs: (HTTPSServer if SSL else HTTPServer)(*args, **dict(itertools.chain(
                kwargs.iteritems(), self._sslargs.iteritems() if SSL else (), (('address_family', address_family),)
            )))

        def serve(address_family, host, port, SSL):
            s = make_server(host, port, app, server_class=server_wrapper(address_family, SSL))
            self._servers.append(s)
            s.serve_forever()

        restrictions = {'users': {}, 'group': {}}
        for (name, restriction) in self._restrictions.iteritems():
            idx = restriction.pop('index', '').strip()
            if idx:
                for (opt, sep) in (('users', ','), ('group', '|')):
                    for val in ifilter_bool(istrip(parse_split(restriction.pop(opt, ''), sep))):
                        if val in restrictions[opt]:
                            if idx not in restrictions[opt][val]:
                                restrictions[opt][val].append(idx)
                        else:
                            restrictions[opt][val] = [idx]

        for (x, y) in itertools.permutations(self._sslargs):
            if not self._sslargs[x]:
                self._sslargs[x] = self._sslargs[y]

        for (af, listen) in self._listen.iteritems():
            for ((host, port), SSL) in listen.iteritems():
                t = Thread(target=serve, args=(af, host, port, SSL))
                t.daemon = True
                t.start()
                self._threads.append(t)

        while True:
            sleep(86400)


def main():
    parser = get_daemon_option_parser()
    for option_group in parser.option_groups:
        if option_group.title == 'Start and stop':
            option_group.add_option(
                '-c', '--cfgdir',
                dest='cfgdir', metavar='DIR', default='/etc/elkproxy', help='read configuration from directory DIR'
            )
            break
    opts, args = parser.parse_args()
    logging.getLogger('daemon').addHandler(logging.StreamHandler())
    try:
        return getattr(
            ELKProxyDaemon(**dict(itertools.ifilter((lambda x: x[1] is not None), vars(opts).iteritems()))),
            args[0]
        )()
    except ELKProxyInternalError as e:
        errno = e.errno[0]

        # TODO: handle errors
        raise


if __name__ == '__main__':
    sys.exit(main())
