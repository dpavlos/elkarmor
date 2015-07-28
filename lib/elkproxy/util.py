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


import itertools
from socket import inet_aton, inet_pton, inet_ntop, AF_INET, error as SocketError


__all__ = ['parse_split', 'normalize_ip', 'istrip', 'ifilter_bool']


def parse_split(subj, sep, esc='\\'):
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


def normalize_ip(af, ip):
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


def istrip(iterable):
    """
    Call .strip of each object yielded by iterable

    :rtype: itertools.imap
    """

    return itertools.imap((lambda x: x.strip()), iterable)


def ifilter_bool(iterable):
    """
    Yield only true values from iterable

    :rtype: itertools.ifilter
    """

    return itertools.ifilter(None, iterable)
