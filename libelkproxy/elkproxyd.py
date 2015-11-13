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
from ConfigParser import RawConfigParser, Error as ConfigParserError
from .daemon import UnixDaemon, get_daemon_option_parser
from .util import *
from .logging_handlers import *
from .http import *
from .app import *


DEVNULL = open(os.devnull, 'r+b')
DEFAULT_LOGIDENT = 'elkproxy'
DEFAULT_LOGLEVEL = logging.INFO

log_lvl = {
    'crit':     logging.CRITICAL,
    'err':      logging.ERROR,
    'warn':     logging.WARNING,
    'info':     logging.INFO,
    'debug':    logging.DEBUG
}


class ELKArmorConfigError(Exception):
    pass


class ELKArmorConfigNetIOError(ELKArmorConfigError):
    pass


class ELKArmorConfigLDAPError(ELKArmorConfigError):
    pass


class ELKArmorConfigElasticsearchError(ELKArmorConfigError):
    pass


class ELKArmorConfigLogError(ELKArmorConfigError):
    pass


class ELKArmorConfigRestrictionsError(ELKArmorConfigError):
    pass


class ELKProxyNoListen(Exception):
    pass


class LDAPBackend(object):
    def __init__(
            self, url, group_base_dn, user_base_dn,
            bind_dn = None, bind_pw = None):
        self._url = url
        self._group_base_dn = group_base_dn
        self._user_base_dn = user_base_dn
        self._bind_dn = bind_dn
        self._bind_pw = bind_pw

        self._bound = False
        self._connection = None
        self._membership_cache = {}

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
            self._connection = None
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

        attrsonly = 0
        if attributes is not None and not attributes:
            # This is actually quite dirty as I was not able to find a way to
            # select "nothing". This will now only omit the values of all
            # attributes but the attribute names itself are still transmitted
            attrsonly = 1

        return self.connection.search_s(
            base_dn, ldap.SCOPE_SUBTREE, search_string, attributes, attrsonly)

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
        membership_cache = self._membership_cache.get(username)
        now = datetime.now()

        if membership_cache is not None and membership_cache['expires'] > now:
            memberships = membership_cache['memberships']
        else:
            user_dn = self.fetch_user_dn(username)
            group_filter = {'objectClass': 'group',
                'member:1.2.840.113556.1.4.1941:': user_dn}
            result = self.search(self._group_base_dn, group_filter, [])
            memberships = frozenset(t[0] for t in result)
            self._membership_cache[username] = {
                'memberships': memberships,
                'expires': now + timedelta(minutes=15)
            }

        return memberships


class ELKProxyDaemon(UnixDaemon):
    name = 'ELK Proxy'

    _cfg_opt_url_rgx = re.compile(r'\Aurl_(?:(begin|end|full)_)?')
    _cfg_opt_url_switch = {None: '{0}', 'begin': r'\A{0}', 'end': r'{0}\Z', 'full': r'\A{0}\Z'}

    def __init__(self, *args, **kwargs):
        self._cfgdir = kwargs.pop('cfgdir')
        self._cfg = {}
        self._elkenv = {}
        self._servers = []
        self._threads = []
        super(ELKProxyDaemon, self).__init__(*args, **kwargs)

    def _load_config_file(self, filename, defaults = None):
        filepath = os.path.join(os.path.abspath(self._cfgdir), filename + '.ini')
        config = RawConfigParser(defaults)

        try:
            with open(filepath) as f:
                config.readfp(f, filename)
        except ConfigParserError as error:
            raise ELKArmorConfigError(
                "The config file {0} is syntactically invalid: {1}"
                "".format(filepath, error))
        except IOError as error:
            if defaults is None:
                raise ELKArmorConfigError(
                    "The config file {0} doesn't exist or isn't readable: {1}"
                    "".format(filepath, error))

        return dict((s, dict(config.items(s))) for s in config.sections())

    def before_daemonize(self):
        # Load the general configuration..
        self._cfg = self._load_config_file('config')

        # ..and validate it
        self._cfg['log'] = self._validate_cfg_log(self._cfg)
        self._cfg['netio'] = self._validate_cfg_netio(self._cfg)
        self._cfg['ldap'] = self._validate_cfg_ldap(self._cfg)
        self._cfg['elasticsearch'] = self._validate_cfg_elasticsearch(self._cfg)

        # Load the restriction configuration and parse/validate it
        self._parse_restrictions(self._load_config_file('restrictions', defaults={}))

        # Set up logging
        logging_cfg = self._cfg['log']

        if logging_cfg['type'] == 'file':
            try:
                log_handler = FileHandler(logging_cfg['path'], logging_cfg['prefix'])
            except IOError as e:
                raise ELKArmorConfigLogError("the log file {0!r} isn't writable: {1!s}".format(logging_cfg['path'], e))
        else:
            log_handler = SysLogHandler(logging_cfg['prefix'])

        root_logger = logging.getLogger()
        root_logger.setLevel(log_lvl[logging_cfg['level']])
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)
        root_logger.addHandler(log_handler)

        self._logger = logging.getLogger(__name__)

    @staticmethod
    def _validate_cfg_netio(cfg):
        cfg = cfg.get('netio', {}).copy()

        # SSL-specific options

        netio = {'sslargs': dict(((k, cfg.pop(k, '') or None) for k in ('keyfile', 'certfile')))}

        # Validate addresses and interfaces

        try:
            if not cfg:
                raise ELKProxyNoListen()

            rAddr = re.compile(r'(.+):(\d+)(?!.)')
            rAddr6 = re.compile(r'\[(.+)\](?!.)')
            resolve = getifaddrs()

            listen = {}
            for (afs, af, afn) in (('', AF_INET, 4), ('6', AF_INET6, 6)):
                listen[af] = {}
                for SSL in ('', '-ssl'):
                    for addr in ifilter_bool(istrip(parse_split(cfg.pop('inet{0}{1}'.format(afs, SSL), ''), ','))):
                        m = rAddr.match(addr)
                        if not m:
                            raise ELKArmorConfigNetIOError(
                                'invalid address to listen on: {0!r} (must be ip:port)'.format(addr)
                            )

                        ip, port = m.groups()
                        try:
                            port = validate_portnum(port)
                        except ValueError:
                            raise ELKArmorConfigNetIOError(
                                'invalid port number to listen on (in address {1!r}): {0!r}'
                                ' (must be a decimal number between 0 and 65535)'.format(port, addr)
                            )

                        if ip == '*':
                            addrs = frozenset(((ipaddr, port) for ipaddr in itertools.chain.from_iterable((
                                iface[af] for iface in resolve.itervalues() if af in iface
                            ))))

                            if not addrs:
                                raise ELKArmorConfigNetIOError('IPv{0} is not available on any interface'.format(afn))
                        else:
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
                                    raise ELKArmorConfigNetIOError(
                                        'IPv{0} is not available on interface {1}'.format(afn, ip)
                                    )

                                ip = resolve[ip][af]
                            elif allowIP:
                                try:
                                    ip = normalize_ip(af, ip)
                                except ValueError:
                                    raise ELKArmorConfigNetIOError("{0!r} isn't a valid IPv{1} address".format(ip, afn))
                            else:
                                raise ELKArmorConfigNetIOError(
                                    "{0!r} is neither a valid IPv{1} address"
                                    " nor an existing interface's name".format(ip, afn)
                                )

                            addrs = frozenset((
                                (ipaddr, port) for ipaddr in ip
                            )) if isinstance(ip, frozenset) else ((ip, port),)

                        for (ip, port) in addrs:
                            if (ip, port) in listen[af]:
                                raise ELKArmorConfigNetIOError(
                                    '{0}:{1} is configured to listen on more than once'.format(ip, port)
                                )

                            listen[af][(ip, port)] = bool(SSL)
                if not listen[af]:
                    del listen[af]

            if not listen:
                raise ELKProxyNoListen()
        except ELKProxyNoListen:
            raise ELKArmorConfigNetIOError('no IP addresses are configured to listen on')

        if any((
            SSL for af in listen.itervalues() for SSL in af.itervalues()
        )) and not any(netio['sslargs'].itervalues()):
            raise ELKArmorConfigNetIOError(
                'some IP addresses are configured to listen on with SSL,'
                ' but the required options for using SSL are missing'
            )

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
            raise ELKArmorConfigLDAPError('config option "group_base_dn" is required')

        try:
            config['user_base_dn'] = cfg['user_base_dn']
        except KeyError:
            raise ELKArmorConfigLDAPError('config option "user_base_dn" is required')

        return config

    @staticmethod
    def _validate_cfg_elasticsearch(cfg):
        cfg = cfg.get('elasticsearch', {}).copy()

        # Host

        host = cfg.pop('host', '').strip() or 'localhost'

        try:
            elsrch = {'host': validate_hostname(host)[1]}
        except SocketError:
            raise ELKArmorConfigElasticsearchError('invalid hostname: {0!r}'.format(host))

        # Protocol

        protocol = cfg.pop('protocol', '').strip() or 'http'

        try:
            elsrch['https'] = {'http': False, 'https': True}[protocol]
        except KeyError:
            raise ELKArmorConfigElasticsearchError(
                'invalid protocol: {0!r} (must be one of the following: http, https)'.format(protocol)
            )

        # Port

        port = cfg.pop('port', '').strip() or 9200

        try:
            elsrch['port'] = validate_portnum(port)
        except ValueError:
            raise ELKArmorConfigElasticsearchError(
                'invalid port number: {0!r} (must be a decimal number between 0 and 65535)'.format(port)
            )

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
                raise ELKArmorConfigLogError(
                    'invalid logging {0}: {1!r} (must be one of the following: {2})'.format(k, v, ', '.join(opts))
                )

        if logging_cfg['type'] == 'file':
            logging_cfg['path'] = fpath = cfg.pop('path', '')
            if not fpath:
                raise ELKArmorConfigLogError("the logging type is 'file', but no file is configured to log into")

        logging_cfg['prefix'] = cfg.pop('prefix', '').strip() or DEFAULT_LOGIDENT

        return logging_cfg

    def cleanup(self):
        for s in self._servers:
            s.shutdown()
        for t in self._threads:
            t.join()
        logging.shutdown()
        super(ELKProxyDaemon, self).cleanup()

    def _parse_restrictions(self, cfg_restrictions):
        raw_restrictions = []
        unrestricted_idxs = {}

        raw_unrestricted_urls = set()
        raw_permitted_urls = []

        for (name, restriction) in cfg_restrictions.iteritems():
            restricted = dict(((
                opt, frozenset(ifilter_bool(istrip(parse_split(restriction.pop(opt, ''), sep))))
            ) for (opt, sep) in (('users', ','), ('group', '|'))))

            unrestricted_idx = '*' in restricted['users']
            if unrestricted_idx:
                restricted['users'] -= frozenset('*')

            urls = frozenset((self._cfg_opt_url_switch[m.group(1)].format(restriction.pop(k)) for (k, m) in (
                (k, self._cfg_opt_url_rgx.match(k)) for k in frozenset(restriction)
            ) if m))

            permissions = itertools.chain.from_iterable((
                itertools.product(*(
                    frozenset(ifilter_bool(parse_split(p, ','))) for p in permission
                )) for permission in restriction.iteritems()
            ))

            if unrestricted_idx:
                for (permission, idx) in permissions:
                    if permission not in unrestricted_idxs:
                        unrestricted_idxs[permission] = set()
                    unrestricted_idxs[permission].add(idx)

                raw_unrestricted_urls.update(urls)
            else:
                raw_restrictions.append((restricted, frozenset(permissions)))
                raw_permitted_urls.append((restricted, urls))

        unrestricted_idxs = dict(((permission, tuple(
            SimplePattern.without_subsets(itertools.imap(SimplePattern, idxs))
        )) for (permission, idxs) in unrestricted_idxs.iteritems()))

        restrictions = {'users': {}, 'group': {}}

        for (restricted, permissions) in raw_restrictions:
            for (opt, vals) in restricted.iteritems():
                for v in vals:
                    if v not in restrictions[opt]:
                        restrictions[opt][v] = {}

                    for (permission, index) in permissions:
                        if permission not in restrictions[opt][v]:
                            restrictions[opt][v][permission] = []
                        restrictions[opt][v][permission].append(SimplePattern(index))

        unrestricted_urls = []
        all_urls = {}

        try:
            for url in raw_unrestricted_urls:
                if url not in all_urls:
                    try:
                        all_urls[url] = re.compile(url)
                    except re.error:
                        bad_url = url
                        raise

                unrestricted_urls.append(all_urls[url])

            permitted_urls = {'users': {}, 'group': {}}

            for (restricted, urls) in raw_permitted_urls:
                for (opt, vals) in restricted.iteritems():
                    for v in vals:
                        compiled_urls = []

                        for url in urls - raw_unrestricted_urls:
                            if url not in all_urls:
                                try:
                                    all_urls[url] = re.compile(url)
                                except re.error:
                                    bad_url = url
                                    raise

                            compiled_urls.append(all_urls[url])

                        if compiled_urls:
                            if v in permitted_urls[opt]:
                                permitted_urls[opt][v].extend(compiled_urls)
                            else:
                                permitted_urls[opt][v] = compiled_urls
        except re.error as e:
            raise ELKArmorConfigRestrictionsError(
                'invalid regular expression for matching a URL ({0!r}): {1!s}'.format(bad_url, e)
            )

        for (opt, vals) in restrictions.iteritems():
            for (v, permissions) in vals.items():
                for (permission, idxs) in permissions.items():
                    idxs = tuple((
                        idx1 for idx1 in SimplePattern.without_subsets(idxs) if not any((
                            idx2.superset(idx1) for idx2 in unrestricted_idxs.get(permission, ())
                        ))
                    ))

                    if idxs:
                        restrictions[opt][v][permission] = idxs
                    else:
                        del restrictions[opt][v][permission]

                if not restrictions[opt][v]:
                    del restrictions[opt][v]

        self._elkenv['restrictions'] = restrictions
        self._elkenv['unrestricted_idxs'] = unrestricted_idxs
        self._elkenv['unrestricted_urls'] = unrestricted_urls
        self._elkenv['permitted_urls'] = permitted_urls

    def run(self):
        http_connector = HTTPConnector(**self._cfg['elasticsearch'])

        sslargs = self._cfg['netio']['sslargs']

        for (x, y) in itertools.permutations(sslargs):
            if not sslargs[x]:
                sslargs[x] = sslargs[y]

        ldap_backend = LDAPBackend(**self._cfg['ldap'])

        self._elkenv['connector'] = http_connector
        self._elkenv['ldap_backend'] = ldap_backend
        self._elkenv['logger'] = self._logger

        def server_wrapper(address_family, SSL):
            return lambda *args, **kwargs: (HTTPSServer if SSL else HTTPServer)(*args, **dict(itertools.chain(
                kwargs.iteritems(),
                sslargs.iteritems() if SSL else (),
                (('address_family', address_family), ('wsgi_env', {'elkproxy': self._elkenv}))
            )))

        for (af, listen) in self._cfg['netio']['listen'].iteritems():
            for ((host, port), ssl) in listen.iteritems():
                try:
                    s = make_server(host, port, app, server_class=server_wrapper(af, ssl))
                except SocketError as e:
                    self._logger.critical('could not listen on {0}:{1} : {2!s}'.format(
                        '[{0}]'.format(host) if ':' in host else host, port, e)
                    )
                    continue

                t = Thread(target=s.serve_forever)
                t.daemon = True
                t.start()
                self._servers.append(s)
                self._threads.append(t)

        while True:
            sleep(86400)

    def handle_reload(self):
        self._parse_restrictions(self._load_config_file('restrictions'))
        new_restriction_env = {
            'restrictions': self._elkenv['restrictions'],
            'unrestricted_idxs': self._elkenv['unrestricted_idxs'],
            'unrestricted_urls': self._elkenv['unrestricted_urls'],
            'permitted_urls': self._elkenv['permitted_urls']
        }
        for server in self._servers:
            server.patch_wsgi_env(new_restriction_env)


def main():
    root_logger = logging.getLogger()
    root_logger.setLevel(DEFAULT_LOGLEVEL)
    root_logger.addHandler(SysLogHandler(DEFAULT_LOGIDENT))

    parser = get_daemon_option_parser()
    for option_group in parser.option_groups:
        if option_group.title == 'Start and stop':
            option_group.add_option(
                '-c', '--cfgdir',
                dest='cfgdir', metavar='DIR', default='/etc/elkproxy', help='read configuration from directory DIR'
            )
            break
    opts, args = parser.parse_args()
    try:
        return getattr(
            ELKProxyDaemon(**dict(itertools.ifilter((lambda x: x[1] is not None), vars(opts).iteritems()))),
            args[0]
        )()
    except ELKArmorConfigError as e:
        try:
            area = {
                ELKArmorConfigNetIOError: 'network I/O',
                ELKArmorConfigLDAPError: 'LDAP',
                ELKArmorConfigElasticsearchError: 'Elasticsearch',
                ELKArmorConfigLogError: 'logging',
                ELKArmorConfigRestrictionsError: 'restrictions'
            }[type(e)]
        except KeyError:
            return 'Could not evaluate configuration: {0!s}'.format(e)

        return 'Invalid {0} configuration: {1!s}'.format(area, e)


if __name__ == '__main__':
    sys.exit(main())
