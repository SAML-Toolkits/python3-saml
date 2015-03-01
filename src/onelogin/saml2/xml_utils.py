# -*- coding: utf-8 -*-

""" OneLogin_Saml2_XML class

Copyright (c) 2015, OneLogin, Inc.
All rights reserved.

Auxiliary class of OneLogin's Python Toolkit.

"""

from os.path import join, dirname
from lxml import etree
from xml.dom import minidom
from onelogin.saml2.constants import OneLogin_Saml2_Constants


class OneLogin_Saml2_XML(object):
    _document_class = minidom.Document
    _element_class = type(etree.Element('root'))
    _node_class = minidom.Element
    _fromstring = etree.fromstring
    _parse_document = minidom.parseString
    _schema_class = etree.XMLSchema
    _text_class = (str, bytes)
    _tostring = etree.tostring

    make_dom = _document_class

    @staticmethod
    def to_string(xml):
        """
        Serialize an element to an encoded string representation of its XML tree.
        :param xml: The root node
        :type xml: str|bytes|xml.dom.minidom.Document|etree.Element
        :returns: string representation of xml
        :rtype: string
        """

        if isinstance(xml, OneLogin_Saml2_XML._text_class):
            return xml
        if isinstance(xml, (OneLogin_Saml2_XML._document_class, OneLogin_Saml2_XML._node_class)):
            return xml.toxml()

        if isinstance(xml, OneLogin_Saml2_XML._element_class):
            return OneLogin_Saml2_XML._tostring(xml)

        raise ValueError("unsupported type %r" % type(xml))

    @staticmethod
    def to_dom(xml):
        """
        Convert xml to dom
        :param xml: The root node
        :type xml: str|bytes|xml.dom.minidom.Document|etree.Element
        :returns: dom
        :rtype: xml.dom.minidom.Document
        """
        if isinstance(xml, OneLogin_Saml2_XML._document_class):
            return xml
        if isinstance(xml, OneLogin_Saml2_XML._node_class):
            return OneLogin_Saml2_XML._parse_document(xml.toxml())
        if isinstance(xml, OneLogin_Saml2_XML._element_class):
            return OneLogin_Saml2_XML._parse_document(OneLogin_Saml2_XML._tostring(xml))
        if isinstance(xml, OneLogin_Saml2_XML._text_class):
            return OneLogin_Saml2_XML._parse_document(xml)
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
        if isinstance(xml, (OneLogin_Saml2_XML._document_class, OneLogin_Saml2_XML._node_class)):
            return OneLogin_Saml2_XML._fromstring(xml.toxml())
        if isinstance(xml, OneLogin_Saml2_XML._text_class):
            return OneLogin_Saml2_XML._fromstring(xml)

        raise ValueError('unsupported type %r' % type(xml))

    @staticmethod
    def set_node_ns_attributes(xml):
        """
        Set minidom.Element Attribute NS
        Note: function does not affect if input is not instance of Element
        :param xml: the element
        :type xml: xml.dom.minidom.Element
        :returns: the input
        :rtype: xml.dom.minidom.Element
        """
        if isinstance(xml, OneLogin_Saml2_XML._node_class):
            xml.setAttributeNS(
                OneLogin_Saml2_Constants.NS_SAMLP,
                'xmlns:samlp',
                OneLogin_Saml2_Constants.NS_SAMLP
            )
            xml.setAttributeNS(
                OneLogin_Saml2_Constants.NS_SAML,
                'xmlns:saml',
                OneLogin_Saml2_Constants.NS_SAML
            )
        return xml

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
        assert isinstance(schema, str)

        try:
            dom = OneLogin_Saml2_XML.to_etree(xml)
        except Exception as e:
            if debug:
                print(e)
            return 'unloaded_xml'

        schema_file = join(dirname(__file__), 'schemas', schema)
        with open(schema_file, 'r') as f_schema:
            xmlschema = OneLogin_Saml2_XML._schema_class(etree.parse(f_schema))

        if not xmlschema.validate(dom):
            if debug:
                print('Errors validating the metadata: ')
                for error in xmlschema.error_log:
                    print(error.message)
            return 'invalid_xml'
        return OneLogin_Saml2_XML.to_dom(dom)

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
