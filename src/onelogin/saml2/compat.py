# -*- coding: utf-8 -*-

""" py3 compatibility class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

"""

from __future__ import absolute_import, print_function, with_statement


if isinstance(b'', type('')):  # py 2.x
    text_types = (basestring,)  # noqa
    str_type = basestring  # noqa

    def utf8(s):
        """  return utf8-encoded string """
        if isinstance(s, basestring):
            return s.decode("utf8")
        return unicode(s)

    def to_string(s):
        """ return string """
        if isinstance(s, unicode):
            return s.encode("utf8")
        return str(s)

    def to_bytes(s):
        """ return bytes """
        return str(s)

else:  # py 3.x
    text_types = (bytes, str)
    str_type = str

    def utf8(s):
        """ return utf8-encoded string """
        if isinstance(s, bytes):
            return s.decode("utf8")
        return str(s)

    def to_string(s):
        """convert to string"""
        if isinstance(s, bytes):
            return s.decode("utf8")
        return str(s)

    def to_bytes(s):
        """return bytes"""
        if isinstance(s, str):
            return s.encode("utf8")
        return bytes(s)
