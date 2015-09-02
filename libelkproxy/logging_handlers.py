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
from time import mktime
from datetime import datetime
from socket import gethostname


__all__ = ['SysLogHandler', 'FileHandler']


months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


class LoggingFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        if datefmt is not None:
            return logging.Formatter.formatTime(self, record, datefmt)

        t = datetime.fromtimestamp(mktime(self.converter(record.created)))
        return '{0} {1: >2d} {2:%H}:{2:%M}:{2:%S}'.format(months[t.month-1], t.day, t)


syslog_lvl = {
    logging.CRITICAL:   syslog.LOG_CRIT,
    logging.ERROR:      syslog.LOG_ERR,
    logging.WARNING:    syslog.LOG_WARNING,
    logging.INFO:       syslog.LOG_INFO,
    logging.DEBUG:      syslog.LOG_DEBUG
}


syslog_formatter = LoggingFormatter('%(levelname)s: %(message)s')


class SysLogHandler(logging.Handler):
    def __init__(self, ident):
        syslog.openlog(ident, syslog.LOG_PID)
        logging.Handler.__init__(self)
        self.formatter = syslog_formatter

    def emit(self, record):
        msg = self.format(record)
        try:
            prio = syslog_lvl[record.levelno]
        except KeyError:
            syslog.syslog(msg)
        else:
            syslog.syslog(prio, msg)


file_formatter = LoggingFormatter('%(asctime)s %(hostname)s %(ident)s[%(process)d]: %(levelname)s: %(message)s')


class FileHandler(logging.FileHandler):
    def __init__(self, filename, ident):
        logging.FileHandler.__init__(self, filename)
        self._ident = ident
        self.formatter = file_formatter

    def format(self, record):
        record.hostname = gethostname()
        record.ident = self._ident
        return logging.FileHandler.format(self, record)
