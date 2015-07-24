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
from errno import *
from itertools import ifilter, imap, islice, chain, permutations
from time import sleep
from os import path
from datetime import datetime
from subprocess import Popen, PIPE
from threading import Thread
from wsgiref.simple_server import WSGIServer, make_server
from ssl import wrap_socket, CERT_NONE
from logging import Handler, CRITICAL, ERROR, WARNING, INFO, DEBUG, getLogger, shutdown, StreamHandler
from syslog import openlog, syslog, LOG_PID, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG
from socket import inet_aton, inet_pton, inet_ntop, AF_INET, AF_INET6, error as SocketError, getaddrinfo
from ConfigParser import SafeConfigParser as ConfigParser, Error as ConfigParserError
from daemon import UnixDaemon, get_daemon_option_parser


DEVNULL = open(os.devnull, 'r+b')

ECFGDIR = 1
ECFGIO = 2
ECFGSYN = 3
ECFGSEM = 4

syslogLvl = {
    CRITICAL:   LOG_CRIT,
    ERROR:      LOG_ERR,
    WARNING:    LOG_WARNING,
    INFO:       LOG_INFO,
    DEBUG:      LOG_DEBUG
}


def parseSplit(subj, sep, esc='\\'):
    """
    Parse subj as a list of strings separated by sep.
        parseSplit('a,b', ',') -> 'a', 'b'
    To get a literal sep inside a list's item, prepend an esc.
        parseSplit('\\,', ',') -> ','
    To get a literal esc, double it.
        parseSplit('\\\\', ',') -> '\\'

    :type subj: str
    :type sep: str
    :type esc: str
    """

    carry = False
    cur = ''
    c = None

    for c in subj:
        if carry:
            cur += c if c in (esc, sep) else esc + c
            carry = False
        elif c == esc:
            carry = True
        elif c == sep:
            yield cur
            cur = ''
        else:
            cur += c

    if c is not None:
        if carry:
            cur += esc
        yield cur


def normalizeIP(af, ip):
    """
    Normalize IP address.
        127.1 -> 127.0.0.1
        0000:0000:0000:0000:0000:0000:0000:0001 -> ::1

    :param af: address family (AF_INET or AF_INET6)
    :param ip: IP address
    :type ip: str

    :returns: normalized IP address
    :rtype: str
    :raises: ValueError
    """

    try:
        return inet_ntop(af, inet_aton(ip) if af == AF_INET else inet_pton(af, ip))
    except (SocketError, ValueError):
        raise ValueError('{0} is not a valid IPv{1} address'.format(repr(ip), 4 if af == AF_INET else 6))


class SysLogHandler(Handler):
    def __init__(self, ident):
        openlog(ident, LOG_PID)
        Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        try:
            prio = syslogLvl[record.levelno]
        except KeyError:
            syslog(msg)
        else:
            syslog(prio, msg)


class FileHandler(Handler):
    def __init__(self, name):
        self._file = open(name, 'a', 1)
        Handler.__init__(self)

    def emit(self, record):
        print >>self._file, '[{0}] [{1}] {2}'.format(
            str(datetime.fromtimestamp(record.created)), record.levelname, self.format(record)
        )

    def flush(self):
        self._file.flush()
        Handler.flush(self)

    def close(self):
        self._file.close()
        Handler.close(self)


class ELKProxyInternalError(Exception):
    def __init__(self, errno, *args):
        self.errno = (errno,) + args
        super(ELKProxyInternalError, self).__init__()


class HTTPServer(WSGIServer):
    def __init__(self, *args, **kwargs):
        self.address_family = kwargs.pop('address_family', AF_INET)
        WSGIServer.__init__(self, *args, **kwargs)


class HTTPSServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        self._sslargs = dict(((k, kwargs.pop(k, '') or None) for k in ('keyfile', 'certfile')))
        HTTPServer.__init__(self, *args, **kwargs)

    def get_request(self):
        s, a = HTTPServer.get_request(self)
        return wrap_socket(s, server_side=True, cert_reqs=CERT_NONE, **self._sslargs), a


def ELKProxyApp(environ, start_response):
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
            cfp = path.join(self._cfgdir, '{0}.ini'.format(cfn))
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

        ### Resolve all net interfaces' IP (v4 and v6) addresses

        rWord = re.compile(r'\S+')
        families = {'inet': 4, 'inet6': 6}

        p = Popen(
            ['ip', '-o', 'addr', 'show'],
            stdin=DEVNULL,
            stdout=PIPE,
            universal_newlines=True
        )

        resolve = {}
        try:
            for (iface, af, ipaddr) in imap(
                (lambda line: tuple(imap((lambda x: x.group(0)), islice(rWord.finditer(line), 1, 4)))),
                ifilter(None, imap(str.strip, p.stdout))
            ):
                try:
                    af = families[af]
                except KeyError:
                    continue

                try:
                    ip = normalizeIP(AF_INET if af == 4 else AF_INET6, ipaddr.rsplit('/', 1)[0])
                except ValueError:
                    raise ELKProxyInternalError(ECFGSEM, 'net-proc-ip', af, iface, ipaddr)

                if iface in resolve:
                    resolve[iface][af] = ip
                else:
                    resolve[iface] = {af: ip}
        finally:
            if p.wait():
                raise ELKProxyInternalError(ECFGSEM, 'net-proc')

        ### Collect all net interfaces w/o an IP address

        rNetDev = re.compile(r'(\S+):')

        try:
            netDev = open('/proc/net/dev')
        except IOError:
            raise ELKProxyInternalError(ECFGSEM, 'net-dev')

        with netDev as netDev:
            for iface in imap(
                (lambda x: x.group(1)),
                ifilter(None, imap(rNetDev.match, ifilter(None, imap(str.strip, netDev))))
            ):
                if iface not in resolve:
                    resolve[iface] = {}

        ### Validate addresses and interfaces

        rAddr = re.compile(r'(.+):(\d+)(?!.)')
        rAddr6 = re.compile(r'\[(.+)\](?!.)')

        listen = {}
        for (afn, afs, af) in ((4, '', AF_INET), (6, '6', AF_INET6)):
            listen[afn] = {}
            for SSL in ('', '-ssl'):
                for addr in ifilter(None, imap(str.strip, parseSplit(
                    netio.pop('inet{0}{1}'.format(afs, SSL), ''), ','
                ))):
                    m = rAddr.match(addr)
                    if not m:
                        raise ELKProxyInternalError(ECFGSEM, 'net-fmt', addr)

                    ip, port = m.groups()
                    port = int(port)
                    if port > 65535:
                        raise ELKProxyInternalError(ECFGSEM, 'net-port', port, addr)

                    allowIP = allowIFace = True
                    if afn == 6:
                        m = rAddr6.match(ip)
                        if m:
                            ip = m.group(1)
                            allowIFace = False
                        else:
                            allowIP = False

                    if allowIFace and ip in resolve:
                        if afn not in resolve[ip]:
                            raise ELKProxyInternalError(ECFGSEM, 'net-af', af, ip)

                        ip = resolve[ip][afn]
                    elif allowIP:
                        try:
                            ip = normalizeIP(af, ip)
                        except ValueError:
                            raise ELKProxyInternalError(ECFGSEM, 'net-ip', afn, ip)
                    else:
                        raise ELKProxyInternalError(ECFGSEM, 'net-iface', ip)

                    nAddr = (ip, port)
                    if nAddr in listen[afn]:
                        raise ELKProxyInternalError(ECFGSEM, 'net-alrdy', addr)

                    listen[afn][nAddr] = bool(SSL)
            if not listen[afn]:
                del listen[afn]

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
                host = normalizeIP(af, host)
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

        self._ldap = dict(chain(
            (('host', host), ('port', port), ('ssl', SSL)),
            ((k, (str if k == 'pass' else str.strip)(ldap.pop(k, ''))) for k in ('user', 'pass', 'rootdn'))
        ))

        ## Logging

        log = cfg['config'].pop('log', {})

        logLvl = {
            'crit':     CRITICAL,
            'err':      ERROR,
            'warn':     WARNING,
            'info':     INFO,
            'debug':    DEBUG
        }
        logging = {}
        for (k, opts) in (('type', ('file', 'syslog')), ('level', tuple(logLvl))):
            v = log.pop(k, '').strip()
            if v not in opts:
                raise ELKProxyInternalError(ECFGSEM, 'log-opt', k, v, opts)

            logging[k] = v

        if logging['type'] == 'file':
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

        log = getLogger()
        log.addHandler(logHandler)
        log.setLevel(logLvl[logging['level']])

        daemonLogger = getLogger('daemon')
        for handler in daemonLogger.handlers:
            daemonLogger.removeHandler(handler)

        self._log = log

    def cleanup(self):
        for s in self._servers:
            s.shutdown()
        for t in self._threads:
            t.join()
        shutdown()
        super(ELKProxyDaemon, self).cleanup()

    def run(self):
        def ServerWrapper(address_family, SSL):
            def ServerWrapper_(*args, **kwargs):
                return (HTTPSServer if SSL else HTTPServer)(*args, **dict(chain(
                    kwargs.iteritems(), self._sslargs.iteritems() if SSL else (), (('address_family', address_family),)
                )))
            return ServerWrapper_

        def serve(address_family, host, port, SSL):
            s = make_server(host, port, ELKProxyApp, server_class=ServerWrapper(address_family, SSL))
            self._servers.append(s)
            s.serve_forever()

        restrictions = {'users': {}, 'group': {}}
        for (name, restriction) in self._restrictions.iteritems():
            idx = restriction.pop('index', '').strip()
            if idx:
                for (opt, sep) in (('users', ','), ('group', '|')):
                    for val in ifilter(None, imap(str.strip, parseSplit(restriction.pop(opt, ''), sep))):
                        if val in restrictions[opt]:
                            if idx not in restrictions[opt][val]:
                                restrictions[opt][val].append(idx)
                        else:
                            restrictions[opt][val] = [idx]

        for (x, y) in permutations(self._sslargs):
            if not self._sslargs[x]:
                self._sslargs[x] = self._sslargs[y]

        for (af, listen) in self._listen.iteritems():
            for ((host, port), SSL) in listen.iteritems():
                t = Thread(target=serve, args=(AF_INET if af == 4 else AF_INET6, host, port, SSL))
                t.daemon = True
                t.start()
                self._threads.append(t)

        while True:
            sleep(86400)


def main():
    parser = get_daemon_option_parser()
    for option_group in parser.option_groups:
        if option_group.title == 'Start':
            option_group.add_option(
                '-c', '--cfgdir',
                dest='cfgdir', metavar='DIR', default='/etc/elkproxy', help='read configuration from directory DIR'
            )
            break
    opts, args = parser.parse_args()
    getLogger('daemon').addHandler(StreamHandler())
    try:
        return getattr(ELKProxyDaemon(**dict(ifilter((lambda x: x[1] is not None), vars(opts).iteritems()))), args[0])()
    except ELKProxyInternalError as e:
        errno = e.errno[0]

        # TODO: handle errors
        raise


if __name__ == '__main__':
    sys.exit(main())
