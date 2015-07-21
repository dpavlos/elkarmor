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
from itertools import ifilter, imap, islice
from time import sleep
from os import path
from subprocess import Popen, PIPE
from socket import inet_aton, inet_pton, inet_ntop, AF_INET, AF_INET6, error as SocketError
from ConfigParser import SafeConfigParser as ConfigParser, Error as ConfigParserError
from daemon import UnixDaemon, get_daemon_option_parser


DEVNULL = open(os.devnull, 'r+b')

ECFGDIR = 1
ECFGIO = 2
ECFGSYN = 3
ECFGSEM = 4


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
    Return normalized IP address. If the address is invalid, return None.
        127.1 -> 127.0.0.1
        0000:0000:0000:0000:0000:0000:0000:0001 -> ::1

    :param af: address family (AF_INET or AF_INET6)
    :param ip: address
    :type ip: str
    :rtype: str|NoneType
    """

    try:
        return inet_ntop(af, inet_aton(ip) if af == AF_INET else inet_pton(af, ip))
    except (SocketError, ValueError):
        return None


class ELKProxyInternalError(Exception):
    def __init__(self, errno):
        self.errno = errno
        super(ELKProxyInternalError, self).__init__()


class ELKProxyDaemon(UnixDaemon):
    name = 'ELK Proxy'

    def __init__(self, *args, **kwargs):
        self._cfgdir = kwargs.pop('cfgdir')
        self._cfg = {}
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
                raise ELKProxyInternalError((ECFGIO, e.errno, cfp))

            cfgParser = ConfigParser()
            with cf as cf:
                try:
                    cfgParser.readfp(cf)
                except ConfigParserError as e:
                    raise ELKProxyInternalError((ECFGSYN, e, cfp))

            cfg[cfn] = dict(((section, dict(cfgParser.items(section, True))) for section in cfgParser.sections()))

        self._restrictions = cfg['restrictions']

        # Validate configuration

        ## Network I/O

        netio = cfg['config'].pop('netio', {})

        ### Check for non-empty Elasticsearch URL

        elsrchURL = netio.pop('elasticsearch', '').strip()
        if not elsrchURL:
            raise ELKProxyInternalError((ECFGSEM, 'net-elsrch'))

        self._elsrchURL = elsrchURL


        if not netio:
            raise ELKProxyInternalError((ECFGSEM, 'net-listen'))

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

                ip = normalizeIP(AF_INET if af == 4 else AF_INET6, ipaddr.rsplit('/', 1)[0])
                if ip is None:
                    raise ELKProxyInternalError((ECFGSEM, 'net-proc-ip', af, iface, ipaddr))

                if iface in resolve:
                    resolve[iface][af] = ip
                else:
                    resolve[iface] = {af: ip}
        finally:
            if p.wait():
                raise ELKProxyInternalError((ECFGSEM, 'net-proc'))

        ### Collect all net interfaces w/o an IP address

        rNetDev = re.compile(r'(\S+):')

        try:
            netDev = open('/proc/net/dev')
        except IOError:
            raise ELKProxyInternalError((ECFGSEM, 'net-dev'))

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
                        raise ELKProxyInternalError((ECFGSEM, 'net-fmt', addr))

                    ip, port = m.groups()
                    port = int(port)
                    if port > 65535:
                        raise ELKProxyInternalError((ECFGSEM, 'net-port', port, addr))

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
                            raise ELKProxyInternalError((ECFGSEM, 'net-af', af, ip))

                        ip = resolve[ip][afn]
                    elif allowIP:
                        nIP = normalizeIP(af, ip)
                        if nIP is None:
                            raise ELKProxyInternalError((ECFGSEM, 'net-ip', afn, ip))

                        ip = nIP
                    else:
                        raise ELKProxyInternalError((ECFGSEM, 'net-iface', ip))

                    nAddr = (ip, port)
                    if nAddr in listen[afn]:
                        raise ELKProxyInternalError((ECFGSEM, 'net-alrdy', addr))

                    listen[afn][nAddr] = bool(SSL)
            if not listen[afn]:
                del listen[afn]

        if not listen:
            raise ELKProxyInternalError((ECFGSEM, 'net-listen'))

        self._listen = listen

    def run(self):
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
    try:
        return getattr(ELKProxyDaemon(**dict(ifilter((lambda x: x[1] is not None), vars(opts).iteritems()))), args[0])()
    except ELKProxyInternalError as e:
        try:
            errno = e.errno[0]
        except TypeError:
            errno = e.errno

        # TODO: handle errors
        raise


if __name__ == '__main__':
    sys.exit(main())
