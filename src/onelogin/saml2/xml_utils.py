# -*- coding: utf-8 -*-

""" OneLogin_Saml2_XML class

Copyright (c) 2015, OneLogin, Inc.
All rights reserved.

Auxiliary class of OneLogin's Python Toolkit.

"""

from os.path import join, dirname
from lxml import etree
from defusedxml.lxml import tostring, fromstring
from onelogin.saml2 import compat
from onelogin.saml2.constants import OneLogin_Saml2_Constants


for prefix, url in OneLogin_Saml2_Constants.NSMAP.items():
    etree.register_namespace(prefix, url)


class OneLogin_Saml2_XML(object):
    _element_class = type(etree.Element('root'))
    _parse_etree = staticmethod(fromstring)
    _schema_class = etree.XMLSchema
    _text_class = compat.text_types
    _unparse_etree = staticmethod(tostring)

    dump = staticmethod(etree.dump)
    make_root = staticmethod(etree.Element)
    make_child = staticmethod(etree.SubElement)
    cleanup_namespaces = staticmethod(etree.cleanup_namespaces)

    @staticmethod
    def to_string(xml, **kwargs):
        """
        Serialize an element to an encoded string representation of its XML tree.
        :param xml: The root node
        :type xml: str|bytes|xml.dom.minidom.Document|etree.Element
        :returns: string representation of xml
        :rtype: string
        """

        if isinstance(xml, OneLogin_Saml2_XML._text_class):
            return xml

        if isinstance(xml, OneLogin_Saml2_XML._element_class):
            OneLogin_Saml2_XML.cleanup_namespaces(xml)
            return OneLogin_Saml2_XML._unparse_etree(xml, **kwargs)

        raise ValueError("unsupported type %r" % type(xml))

    @staticmethod
    def to_etree(xml):
        """
        Parses an XML document or fragment from a string.
        :param xml: the string to parse
        :type xml: str|bytes|xml.dom.minidom.Document|etree.Element
        :returns: the root node
        :rtype: OneLogin_Saml2_XML._element_class
        """
        if isinstance(xml, OneLogin_Saml2_XML._element_class):
            return xml
        if isinstance(xml, OneLogin_Saml2_XML._text_class):
            return OneLogin_Saml2_XML._parse_etree(xml)

        raise ValueError('unsupported type %r' % type(xml))

    @staticmethod
    def validate_xml(xml, schema, debug=False):
        """
        Validates a xml against a schema
        :param xml: The xml that will be validated
        :type xml: str|bytes|xml.dom.minidom.Document|etree.Element
        :param schema: The schema
        :type schema: string
        :param debug: If debug is active, the parse-errors will be showed
        :type debug: bool
        :returns: Error code or the DomDocument of the xml
        :rtype: xml.dom.minidom.Document
        """

        assert isinstance(schema, compat.str_type)
        try:
            xml = OneLogin_Saml2_XML.to_etree(xml)
        except Exception as e:
            if debug:
                print(e)
            return 'unloaded_xml'

        schema_file = join(dirname(__file__), 'schemas', schema)
        with open(schema_file, 'r') as f_schema:
            xmlschema = OneLogin_Saml2_XML._schema_class(etree.parse(f_schema))

        if not xmlschema.validate(xml):
            if debug:
                print('Errors validating the metadata: ')
                for error in xmlschema.error_log:
                    print(error.message)
            return 'invalid_xml'
        return xml

    @staticmethod
    def query(dom, query, context=None):
        """
        Extracts nodes that match the query from the Element

        :param dom: The root of the lxml objet
        :type: Element

        :param query: Xpath Expresion
        :type: string

        :param context: Context Node
        :type: DOMElement

        :returns: The queried nodes
        :rtype: list
        """
        if context is None:
            return dom.xpath(query, namespaces=OneLogin_Saml2_Constants.NSMAP)
        else:
            return context.xpath(query, namespaces=OneLogin_Saml2_Constants.NSMAP)

    @staticmethod
    def extract_tag_text(xml, tagname):
        open_tag = compat.to_bytes("<%s" % tagname)
        close_tag = compat.to_bytes("</%s>" % tagname)

        xml = OneLogin_Saml2_XML.to_string(xml)
        start = xml.find(open_tag)
        assert start != -1

        end = xml.find(close_tag, start) + len(close_tag)
        assert end != -1
        return compat.to_string(xml[start:end])
