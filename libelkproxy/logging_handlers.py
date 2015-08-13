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


import logging
import syslog
from datetime import datetime


__all__ = ['SysLogHandler', 'FileHandler']


syslog_lvl = {
    logging.CRITICAL:   syslog.LOG_CRIT,
    logging.ERROR:      syslog.LOG_ERR,
    logging.WARNING:    syslog.LOG_WARNING,
    logging.INFO:       syslog.LOG_INFO,
    logging.DEBUG:      syslog.LOG_DEBUG
}


class SysLogHandler(logging.Handler):
    def __init__(self, ident):
        syslog.openlog(ident, syslog.LOG_PID)
        logging.Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        try:
            prio = syslog_lvl[record.levelno]
        except KeyError:
            syslog.syslog(msg)
        else:
            syslog.syslog(prio, msg)


class FileHandler(logging.Handler):
    def __init__(self, name):
        self._file = open(name, 'a', 1)
        logging.Handler.__init__(self)

    def emit(self, record):
        print >>self._file, '[{0}] [{1}] {2}'.format(
            str(datetime.fromtimestamp(record.created)), record.levelname, self.format(record)
        )

    def flush(self):
        self._file.flush()
        logging.Handler.flush(self)

    def close(self):
        self._file.close()
        logging.Handler.close(self)
