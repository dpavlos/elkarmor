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


import sys
import os
import re
import itertools
import logging
import ldap
from errno import *
from time import sleep
from threading import Thread
from wsgiref.simple_server import make_server
from datetime import datetime, timedelta
from ConfigParser import SafeConfigParser as ConfigParser, Error as ConfigParserError
from .daemon import UnixDaemon, get_daemon_option_parser
from .util import *
from .logging_handlers import *
from .http import *
from .app import *


DEVNULL = open(os.devnull, 'r+b')

ECFGDIR = 1
ECFGIO = 2
ECFGSYN = 3
ECFGSEM = 4

log_lvl = {
    'crit':     logging.CRITICAL,
    'err':      logging.ERROR,
    'warn':     logging.WARNING,
    'info':     logging.INFO,
    'debug':    logging.DEBUG
}


class ELKProxyInternalError(Exception):
    def __init__(self, errno, *args):
        self.errno = (errno,) + args
        super(ELKProxyInternalError, self).__init__()


class LDAPBackend(object):
    def __init__(
            self, url, group_base_dn, user_base_dn,
            bind_dn = None, bind_pw = None):
        self._url = url
        self._group_base_dn = group_base_dn
        self._user_base_dn = user_base_dn
        self._bind_dn = bind_dn
        self._bind_pw = bind_pw

        # {'user': (frozenset(['group'...]), expires)}
        self._group_memberships = {}
        self._bound = False
        self._connection = None

    @property
    def connection(self):
        if self._connection is None:
            self._connection = ldap.initialize(self._url)

        return self._connection

    def bind(self):
        if (not self._bound
            and self._bind_dn is not None
            and self._bind_pw is not None):

            self.connection.simple_bind_s(self._bind_dn, self._bind_pw)
            self._bound = True

    def unbind(self):
        if self._bound:
            self.connection.unbind()
            self._bound = False

    def search(self, base_dn, search_filter, attributes = None):
        if len(search_filter) > 1:
            search_string = '(&('
            search_string += ')('.join(
                '{0}={1}'.format(k, v) for k, v in search_filter.iteritems())
            search_string += '))'
        elif len(search_filter) > 0:
            search_string = '({0}={1})'.format(
                search_filter.keys()[0], search_filter.values()[0])
        else:
            search_string = '(objectClass=*)'

        return self.connection.search_s(
            base_dn, ldap.SCOPE_SUBTREE, search_string, attributes)

    def fetch_user_dn(self, username):
        result = self.search(
            self._user_base_dn,
            {'objectClass': 'user', 'sAMAccountName': username}, [])
        if len(result) == 0:
            raise ldap.NO_RESULTS_RETURNED(
                {'desc': 'No DN found for user {0}'.format(username)})
        elif len(result) > 1:
            raise ldap.LDAPError(
                {'desc': 'Multiple DNs found for user {0}'.format(username)})

        return result[0][0]

    def get_group_memberships(self, username):
        memberships = self._group_memberships.get(user, False)
        now = datetime.now()

        if memberships and memberships[1] > now:
            memberships = memberships[0]
        else:
            conn = ldap.initialize(self._url)
            if self._starttls:
                try:
                    conn.start_tls_s()
                except ldap.LDAPError:
                    pass

            conn.simple_bind_s(self._user, self._passwd)
            try:
                # TODO: connect to LDAP server and fetch the user's groups
                memberships = frozenset() if 'user exists' else None
            finally:
                conn.unbind_s()

            self._group_memberships[user] = (memberships, now + timedelta(minutes=15))

        if memberships is None:
            raise KeyError('no such user: ' + repr(user))

        return memberships


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

        self._cfg = dict(((k, getattr(self, '_validate_cfg_' + k)(cfg['config'])) for k in (
            'netio', 'elasticsearch', 'ldap', 'log'
        )))

        # Set up logging

        logging_cfg = self._cfg['log']

        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(log_lvl[logging_cfg['level']])

        try:
            self._logger.addHandler(FileHandler(logging_cfg['path'], logging_cfg['prefix']) if (
                logging_cfg['type'] == 'file'
            ) else SysLogHandler(logging_cfg['prefix']))
        except IOError as e:
            raise ELKProxyInternalError(ECFGSEM, 'log-io', logging_cfg['path'], e.errno)

        daemon_logger = logging.getLogger('libelkproxy.daemon')
        for handler in daemon_logger.handlers:
            daemon_logger.removeHandler(handler)

    @staticmethod
    def _validate_cfg_netio(cfg):
        cfg = cfg.get('netio', {}).copy()

        # SSL-specific options

        netio = {'sslargs': dict(((k, cfg.pop(k, '') or None) for k in ('keyfile', 'certfile')))}

        # Validate addresses and interfaces

        if not cfg:
            raise ELKProxyInternalError(ECFGSEM, 'net-listen')

        rAddr = re.compile(r'(.+):(\d+)(?!.)')
        rAddr6 = re.compile(r'\[(.+)\](?!.)')
        resolve = getifaddrs()

        listen = {}
        for (afs, af) in (('', AF_INET), ('6', AF_INET6)):
            listen[af] = {}
            for SSL in ('', '-ssl'):
                for addr in ifilter_bool(istrip(parse_split(cfg.pop('inet{0}{1}'.format(afs, SSL), ''), ','))):
                    m = rAddr.match(addr)
                    if not m:
                        raise ELKProxyInternalError(ECFGSEM, 'net-fmt', addr)

                    ip, port = m.groups()
                    try:
                        port = validate_portnum(port)
                    except ValueError:
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

        if any((
            SSL for af in listen.itervalues() for SSL in af.itervalues()
        )) and not any(netio['sslargs'].itervalues()):
            raise ELKProxyInternalError(ECFGSEM, 'net-ssl')

        netio['listen'] = listen


        return netio

    @staticmethod
    def _validate_cfg_ldap(cfg):
        cfg = cfg.get('ldap', {})

        config = {}
        config['url'] = cfg.get('url', 'ldap://localhost')
        config['bind_dn'] = cfg.get('bind_dn')
        config['bind_pw'] = cfg.get('bind_pw')

        try:
            config['group_base_dn'] = cfg['group_base_dn']
        except KeyError:
            raise ELKProxyInternalError(
                ECFGSEM,
                'LDAP config option "group_base_dn" is required'
            )

        try:
            config['user_base_dn'] = cfg['user_base_dn']
        except KeyError:
            raise ELKProxyInternalError(
                ECFGSEM,
                'LDAP config option "user_base_dn" is required'
            )

        return config

    @staticmethod
    def _validate_cfg_elasticsearch(cfg):
        cfg = cfg.get('elasticsearch', {}).copy()

        # Host

        host = cfg.pop('host', '').strip() or 'localhost'

        try:
            elsrch = {'host': validate_hostname(host)[1]}
        except SocketError:
            raise ELKProxyInternalError(ECFGSEM, 'elsrch-host', host)

        # Protocol

        protocol = cfg.pop('protocol', '').strip() or 'http'

        try:
            elsrch['https'] = {'http': False, 'https': True}[protocol]
        except KeyError:
            raise ELKProxyInternalError(ECFGSEM, 'elsrch-proto', protocol)

        # Port

        port = cfg.pop('port', '').strip() or 9200

        try:
            elsrch['port'] = validate_portnum(port)
        except ValueError:
            raise ELKProxyInternalError(ECFGSEM, 'elsrch-port', port)

        # Base URL

        elsrch['baseurl'] = cfg.pop('baseurl', '').strip() or '/'


        return elsrch

    @staticmethod
    def _validate_cfg_log(cfg):
        cfg = cfg.get('log', {}).copy()

        logging_cfg = {}
        for (k, opts) in (('type', ('file', 'syslog')), ('level', tuple(log_lvl))):
            logging_cfg[k] = v = cfg.pop(k, '').strip()
            if v not in opts:
                raise ELKProxyInternalError(ECFGSEM, 'log-opt', k, v, opts)

        if logging_cfg['type'] == 'file':
            logging_cfg['path'] = fpath = cfg.pop('path', '')
            if not fpath:
                raise ELKProxyInternalError(ECFGSEM, 'log-path')

        logging_cfg['prefix'] = cfg.pop('prefix', '').strip() or 'elkproxyd'

        return logging_cfg

    def cleanup(self):
        for s in self._servers:
            s.shutdown()
        for t in self._threads:
            t.join()
        logging.shutdown()
        super(ELKProxyDaemon, self).cleanup()

    def run(self):
        http_connector = HTTPConnector(**self._cfg['elasticsearch'])

        raw_restrictions = []
        unrestricted = {'users': set(), 'group': set()}

        for (name, restriction) in self._restrictions.iteritems():
            restricted = ((
                opt, ifilter_bool(istrip(parse_split(restriction.pop(opt, ''), sep)))
            ) for (opt, sep) in (('users', ','), ('group', '|')))

            if restriction.pop('passthrough', '').strip().lower() == 'true':
                for (opt, vals) in restricted:
                    for v in vals:
                        unrestricted[opt].add(v)
                continue

            restricted = dict(((opt, frozenset(vals)) for (opt, vals) in restricted))

            raw_restrictions.append((
                restricted,
                frozenset(itertools.chain.from_iterable((
                    itertools.product(*itertools.imap((
                        lambda x: frozenset(ifilter_bool(parse_split(x, ',')))
                    ), permission)) for permission in restriction.iteritems()
                )))
            ))

        restrictions = {'users': {}, 'group': {}}

        for (restricted, permissions) in raw_restrictions:
            for (opt, vals) in restricted.iteritems():
                for v in vals:
                    if v not in unrestricted[opt]:
                        if v not in restrictions[opt]:
                            restrictions[opt][v] = {}

                        for (permission, index) in permissions:
                            if permission not in restrictions[opt][v]:
                                restrictions[opt][v][permission] = []
                            restrictions[opt][v][permission].append(SimplePattern(index))

        del raw_restrictions

        for (opt, vals) in restrictions.iteritems():
            for (v, permissions) in vals.iteritems():
                for (permission, idxs) in permissions.iteritems():
                    restrictions[opt][v][permission] = tuple(SimplePattern.without_subsets(idxs))

        sslargs = self._cfg['netio']['sslargs']

        for (x, y) in itertools.permutations(sslargs):
            if not sslargs[x]:
                sslargs[x] = sslargs[y]

        ldap_backend = LDAPBackend(**self._cfg['ldap'])
        ldap_backend.bind()

        def server_wrapper(address_family, SSL):
            return lambda *args, **kwargs: (HTTPSServer if SSL else HTTPServer)(*args, **dict(itertools.chain(
                kwargs.iteritems(),
                sslargs.iteritems() if SSL else (),
                (('address_family', address_family), ('wsgi_env', {'elkproxy': {
                    'connector': http_connector,
                    'restrictions': restrictions,
                    'unrestricted': unrestricted,
                    'ldap_backend': ldap_backend,
                    'logger': self._logger
                }}))
            )))

        for (af, listen) in self._cfg['netio']['listen'].iteritems():
            for ((host, port), ssl) in listen.iteritems():
                s = make_server(host, port, app, server_class=server_wrapper(af, ssl))
                t = Thread(target=s.serve_forever)
                t.daemon = True
                t.start()
                self._servers.append(s)
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
    logging.getLogger('libelkproxy.daemon').addHandler(logging.StreamHandler())
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
