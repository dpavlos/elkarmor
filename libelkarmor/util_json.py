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


import itertools
import json


__all__ = ['unicode_to_str', 'ScalarWrapper', 'JSONHighlightPart']


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


class ScalarWrapper(object):
    """
    Wraps any object to diffecence between multiple instances with the same value at different positions

    assert 1 is 1
    assert ScalarWrapper(1) is not ScalarWrapper(1)
    """

    def __init__(self, obj):
        """
        :param obj: the object to wrap
        """

        self._obj = obj

    def get_wrapped(self):
        """
        :return: the wrapped object
        """

        return self._obj

    def __hash__(self):
        return hash(self._obj)

    def __eq__(self, other):
        """
        :rtype: bool
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return self._obj == other._obj

    def __repr__(self):
        """
        :rtype: str
        """

        return '{0}({1!r})'.format(type(self).__name__, self._obj)

    @classmethod
    def wrap_recursive(cls, j):
        """
        Return a copy of j with all objects inside dict or list wrapped in ScalarWrapper

        :param j: parsed JSON as returned by json.loads()
        """

        return cls(
            dict((
                itertools.imap(cls.wrap_recursive, x) for x in j.iteritems()
            )) if isinstance(j, dict) else map(
                cls.wrap_recursive, j
            ) if isinstance(j, list) else j
        )

    @classmethod
    def unwrap_recursive(cls, j):
        """
        The inverse of wrap_recursive()

        :param j: wrapped JSON as returned by wrap_recursive()
        :type j: ScalarWrapper
        """

        unwrapped = j.get_wrapped()
        return dict((
            itertools.imap(cls.unwrap_recursive, x) for x in unwrapped.iteritems()
        )) if isinstance(unwrapped, dict) else map(
            cls.unwrap_recursive, unwrapped
        ) if isinstance(unwrapped, list) else unwrapped


class JSONHighlightPart(object):
    """
    Shows an exact part of a JSON value (e.g. a semantic error)
    """

    def __init__(self, whole_json):
        """
        :param whole_json: the JSON value to show an exact part of
        :type whole_json: ScalarWrapper
        """

        self._whole_json = whole_json

    def render_2d(self, target):
        """
        :param target: the exact part of the JSON value to show
        :type target: ScalarWrapper
        :return: the JSON value rendered 2-dimensional with target ASCII-highlighted
        :rtype: str
        """

        try:
            self._render_2d(self._whole_json, target)
        except self._RenderStop as e:
            return str(e)

    @classmethod
    def _render_2d(cls, current_wrapped, target, result='', indent=0, curpos=0):
        """
        helper method for .render_2d() for recursive rendering

        :type current_wrapped: ScalarWrapper
        :type target: ScalarWrapper
        :type result: str
        :type indent: int
        :type curpos: int
        :rtype: str
        :raise cls._RenderStop:
        """

        current = current_wrapped.get_wrapped()

        if current_wrapped is target:
            raise cls._RenderStop('{0}{1}\n{2}^'.format(
                result,
                (
                    '{' if current else '{}'
                ) if isinstance(current, dict) else (
                    '[' if current else '[]'
                ) if isinstance(current, list) else json.dumps(current),
                '-' * curpos
            ))

        next_indent = indent + 4

        if isinstance(current, dict):
            if current:
                first = True
                for (k, v) in current.iteritems():
                    result = cls._render_2d(k, target, '{0}{1}\n{2}'.format(
                        result, '{' if first else ',', ' ' * next_indent
                    ), next_indent, next_indent) + ': '

                    result = cls._render_2d(v, target, result, next_indent, len(result.rsplit('\n', 1)[-1]))

                    if first:
                        first = False

                result += '\n{0}}}'.format(' ' * indent)
            else:
                result += '{}'
        elif isinstance(current, list):
            if current:
                first = True
                for i in current:
                    result = cls._render_2d(i, target, '{0}{1}\n{2}'.format(
                        result, '[' if first else ',', ' ' * next_indent
                    ), next_indent, next_indent)

                    if first:
                        first = False

                result += '\n{0}]'.format(' ' * indent)
            else:
                result += '[]'
        else:
            result += json.dumps(current)

        return result

    def render_flat(self, target):
        """
        :param target: the exact part of the JSON value to show
        :type target: ScalarWrapper
        :return: the JSON value rendered 1-dimensional with target ASCII-highlighted
        :rtype: str
        """

        try:
            self._render_flat(self._whole_json, target)
        except self._RenderStop as e:
            return str(e)

    @classmethod
    def _render_flat(cls, current_wrapped, target, result=''):
        """
        helper method for .render_flat() for recursive rendering

        :type current_wrapped: ScalarWrapper
        :type target: ScalarWrapper
        :type result: str
        :rtype: str
        :raise cls._RenderStop:
        """

        current = current_wrapped.get_wrapped()

        if current_wrapped is target:
            raise cls._RenderStop('{0}{1}  <----'.format(
                result,
                (
                    '{' if current else '{}'
                ) if isinstance(current, dict) else (
                    '[' if current else '[]'
                ) if isinstance(current, list) else json.dumps(current)
            ))

        if isinstance(current, dict):
            if current:
                result += '{'

                first = True
                for (k, v) in current.iteritems():
                    result = cls._render_flat(v, target, cls._render_flat(
                        k, target, result if first else result + ', '
                    ) + ': ')

                    if first:
                        first = False

                result += '}'
            else:
                result += '{}'
        elif isinstance(current, list):
            if current:
                result += '['

                first = True
                for i in current:
                    result = cls._render_flat(i, target, result if first else result + ', ')

                    if first:
                        first = False

                result += ']'
            else:
                result += '[]'
        else:
            result += json.dumps(current)

        return result

    class _RenderStop(Exception):
        pass
