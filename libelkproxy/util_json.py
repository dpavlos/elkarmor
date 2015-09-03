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


__all__ = ['unicode_to_str']


def unicode_to_str(j, encoding='utf_8'):
    """
    Return a copy of j with all unicode instances .encode()d with given encoding (recursively)

    :param j: parsed JSON as returned by json.loads()
    :type encoding: str
    """

    if isinstance(j, dict):
        return dict(((unicode_to_str(y, encoding=encoding) for y in x) for x in j.iteritems()))

    if isinstance(j, list):
        return [unicode_to_str(x, encoding=encoding) for x in j]

    return j.encode(encoding) if isinstance(j, unicode) else j
