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
import re
import netifaces
from httplib import HTTPConnection, HTTPSConnection
from socket import inet_aton, inet_pton, inet_ntop, AF_INET, AF_INET6, error as SocketError, getaddrinfo


__all__ = [
    'parse_split', 'normalize_ip', 'istrip', 'ifilter_bool', 'getifaddrs', 'validate_hostname', 'validate_portnum',
    'HTTPConnector', 'AF_INET', 'AF_INET6', 'SocketError', 'normalize_pattern', 'SimplePattern'
]


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


netifaces_socket = {
    netifaces.AF_INET:  AF_INET,
    netifaces.AF_INET6: AF_INET6
}


def getifaddrs():
    """
    Resolve all net interfaces' IP (v4 and v6) addresses

    :return: {iface: {afamily: addr}}
    :rtype: dict
    """

    return dict((
        (
            iface,
            dict((
                (
                    af,
                    normalize_ip(af, addr[0].split('%', 1)[0])
                ) for (af, addr) in (
                    (
                        netifaces_socket[af],
                        tuple(itertools.islice((
                            v for ainfo in ainfos for (k, v) in ainfo.iteritems() if k == 'addr'
                        ), 0, 1))
                    ) for (af, ainfos) in netifaces.ifaddresses(iface).iteritems() if af in netifaces_socket
                ) if addr
            ))
        ) for iface in netifaces.interfaces()
    ))


def validate_hostname(hostname):
    """
    Validate the given hostname

    :param hostname: the hostname to validate
    :type hostname: str

    :return: (af, ip)
        af: if hostname is a valid IP v4 or v6 address, AF_INET or AF_INET6, respectively (None otherwise)
        ip: if hostname is a valid IP (v4 or v6) address,
            the hostname normalized by normalize_ip() (the unmodified hostname otherwise)
    :rtype: tuple
    :raises: SocketError  if the hostname is not an IP address and can't be resolved by getaddrinfo()
    """

    for af in (AF_INET6, AF_INET):
        try:
            return af, normalize_ip(af, hostname)
        except ValueError:
            pass
    getaddrinfo(hostname, None)
    return None, hostname


def validate_portnum(portnum):
    """
    Validate the given (TCP) port number

    :param portnum: the (TCP) port number to validate
    :type portnum: str|int

    :return: the given port number as integer
    :raises: ValueError  in case of an invalid integer given or not 0-65535
    """

    portnum = int(portnum)
    if portnum not in xrange(65536):
        raise ValueError('invalid port number: {0} (must be >= 0 and <= 65535)'.format(portnum))
    return portnum


def make_httpconn_cls(basecls):
    class HTTPConnCls(basecls):
        def __init__(self, *args, **kwargs):
            self.baseurl = kwargs.pop('baseurl', '')
            basecls.__init__(self, *args, **kwargs)

        def request(self, method, url, *args, **kwargs):
            if url:
                url = '/' + url.lstrip('/')
            return basecls.request(self, method, (self.baseurl + url) or '/', *args, **kwargs)

    return HTTPConnCls


HTTPConn = make_httpconn_cls(HTTPConnection)
HTTPSConn = make_httpconn_cls(HTTPSConnection)


class HTTPConnector(object):
    """
    Store parameters for creating an HTTP(S) connection (more than once)
    """

    def __init__(self, host, port=None, https=False, baseurl=''):
        """
        Validate parameters and construct object

        :param host: the host to connect to
        :type host: str
        :param port: the (TCP) destination port (default: one of 80 and 443)
        :type port: int|str
        :param https: whether to use SSL
        :type https: bool
        :param baseurl: the prefix to prepend to every URL on .request()
        :type baseurl: str

        :raises: SocketError  in case of an invalid hostname
        :raises: ValueError  in case of an invalid port number
        """

        af, host = validate_hostname(host)
        self.host = host.join('[]') if af is not None and af == AF_INET6 else host

        self.port = (443 if https else 80) if port is None else validate_portnum(port)
        self.connector_class = HTTPSConn if https else HTTPConn

        baseurl = baseurl.strip('/')
        self.baseurl = baseurl and '/' + baseurl

    def __call__(self):
        """
        Create a new HTTP(S) connection based on the stored parameters

        :rtype: HTTPConnection
        """

        return self.connector_class(self.host, self.port, baseurl=self.baseurl)


multi_asterisk = re.compile(r'\*{2,}')


def normalize_pattern(pattern):
    """
    Return the given pattern with sequences of multiple asterisks replaced by one asterisk

    :type pattern: str
    :rtype: str
    """

    return multi_asterisk.sub('*', pattern)


class SimpleSubPatternChar(str):
    """
    A subpattern (of SimplePattern) which consumes one specific character
    """

    def consume(self, pattern):
        """
        If pattern is not empty and its first element is equal to self, yield pattern without its first element

        :type pattern: tuple
        """

        if pattern and isinstance(pattern[0], SimpleSubPatternChar) and pattern[0] == self:
            yield pattern[1:]

    def __repr__(self):
        """
        :rtype: str
        """

        return '{0}({1})'.format(type(self).__name__, super(SimpleSubPatternChar, self).__repr__())


class SimpleSubPatternAsterisk(object):
    """
    A subpattern (of SimplePattern) which consumes everything
    """

    @staticmethod
    def consume(pattern):
        """
        Yield all possible variants of pattern without some leading elements
            (1, 2, 3) -> (), (3,), (2, 3), (1, 2, 3)

        :type pattern: tuple
        """

        for i in xrange(len(pattern), -1, -1):
            yield pattern[i:]

    @classmethod
    def __repr__(cls):
        """
        :rtype: str
        """

        return cls.__name__ + '()'

    def __hash__(self):
        return 0

    def __eq__(self, other):
        return type(self) is type(other)


simple_subpattern_asterisk = SimpleSubPatternAsterisk()


class SimplePattern(tuple):
    """
    A pattern (with wildcards) which can be compared with others
    """

    def __new__(cls, pattern, literal=False):
        """
        :param pattern: the pattern as string
        :type pattern: str
        """

        pattern = normalize_pattern(pattern)
        self = super(SimplePattern, cls).__new__(cls, pattern and (
            itertools.imap(SimpleSubPatternChar, pattern) if literal else ((
                simple_subpattern_asterisk if c == '*' else SimpleSubPatternChar(c)
            ) for c in pattern)
        ))
        self._representation = '{0}({1}{2})'.format(
            cls.__name__, repr(pattern), ', literal=True' if literal else ''
        )
        return self

    def __init__(self, pattern, literal=False):
        super(SimplePattern, self).__init__()

    def superset(self, other):
        """
        Check whether this pattern is a superset of another one

        :param other: the other pattern to compare this one with
        :type other: SimplePattern
        :rtype: bool
        """

        if self == other:
            return True

        for x in self._consume(self, other):
            return True
        return False

    @classmethod
    def _consume(cls, p1, p2):
        """
        Helper method for .superset() for recursive iteration

        :type p1: tuple
        :type p2: tuple
        """

        if p1:
            for remainder in p1[0].consume(p2):
                for result in cls._consume(p1[1:], remainder):
                    yield result
        elif not p2:
            yield None

    def __repr__(self):
        """
        :rtype: str
        """

        return self._representation


def json_unicode_to_str(j, encoding='utf_8'):
    """
    Return a copy of j with all unicode instances .encode()d with given encoding (recursively)

    :param j: parsed JSON as returned by json.loads()
    :type encoding: str
    """

    if isinstance(j, dict):
        return dict(((json_unicode_to_str(y, encoding=encoding) for y in x) for x in j.iteritems()))

    if isinstance(j, list):
        return [json_unicode_to_str(x, encoding=encoding) for x in j]

    return j.encode(encoding) if isinstance(j, unicode) else j
