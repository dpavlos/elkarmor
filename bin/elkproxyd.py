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
from itertools import ifilter
from time import sleep
from daemon import UnixDaemon, get_daemon_option_parser


class ELKProxyDaemon(UnixDaemon):
    name = 'ELK Proxy'

    def before_daemonize(self):
        pass

    def run(self):
        while True:
            sleep(86400)


def main():
    opts, args = get_daemon_option_parser().parse_args()
    return getattr(ELKProxyDaemon(**dict(ifilter((lambda x: x[1] is not None), vars(opts).iteritems()))), args[0])()


if __name__ == '__main__':
    sys.exit(main())
