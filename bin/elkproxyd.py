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
from itertools import ifilter, imap
from time import sleep
from os import path
from socket import inet_aton, inet_pton, inet_ntop, AF_INET, error as SocketError
from ConfigParser import SafeConfigParser as ConfigParser, Error as ConfigParserError
from daemon import UnixDaemon, get_daemon_option_parser


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
        if not os.access(self._cfgdir, os.R_OK | os.X_OK):
            raise ELKProxyInternalError(ECFGDIR)

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

        # TODO: validate

        for (cfn, cfo) in cfg.iteritems():
            setattr(self, '_' + cfn, cfo)

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
