# Copyright (C) 2017 Alessandro De Vito (@_cube0x8)
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
"""
@author: Alessandro De Vito (@_cube0x8)
@license: GNU General Public License 2.0 or later
"""

import libchrome_5803029110 as libchrome
import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.common as common
import volatility.win32 as win32
import volatility.utils as utils
import volatility.scan as scan
import volatility.utils as utils
from volatility.renderers import TreeGrid
import time
import pdb
import ipdb

class DocumentFlagScanner(scan.ScannerCheck):
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + 16, 0x4)
        flag = struct.unpack("<I", data)[0]
        if flag in libchrome.Document_nodeFlag:
            # debug.info("Document flag hit! Return...")
            return True
        return False

    def skip(self, data, offset):
        return 8


class DocumentLocalDOMWindowPointerScanner(scan.ScannerCheck):
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # debug.info("check if pointer is not NULL")
        LocalDOMWindow_p = self.address_space.read(offset + libchrome.LocalDOMWindow_offset, 0x8)
        LocalDOMWindow_p = struct.unpack("<Q", LocalDOMWindow_p)[0]
        if LocalDOMWindow_p != 0:
            return True
        return False

    def skip(self, data, offset):
        return 8


class DocumentScanner(scan.BaseScanner):
    checks = [("DocumentFlagScanner", {}),
              ("DocumentLocalDOMWindowPointerScanner", {})
              ]


class DOMScanner():
    def __init__(self, rootNode, address_space):
        self.rootNode = rootNode
        self.proc_as = address_space
        self.dom = []

    def wrap(self, node):
        if node.nodeFlags() in libchrome.containerNodeFlags:
            node = obj.Object("Element", vm=self.proc_as, offset=node.obj_offset)
            if node.tagName == "form":
                node = obj.Object("HTMLElementForm", vm=self.proc_as, offset=node.obj_offset)
            if node.tagName == "iframe":
                node = obj.Object("HTMLIframeElement", vm=self.proc_as, offset=node.obj_offset)
            if node.tagName == "a":
                node = obj.Object("HTMLAnchorElement", vm=self.proc_as, offset=node.obj_offset)
        elif node.nodeFlags() in libchrome.otherFlags:
            node = obj.Object("TextNode", vm=self.proc_as, offset=node.obj_offset)
        return node

    def scan(self):
        HTMLHtmlElement = obj.Object("DOMNode", vm=self.proc_as, offset=self.rootNode)
        # pdb.set_trace()
        self.parseDOMTree(HTMLHtmlElement)
        return self.dom

    def parseDOMTree(self, root):
        root = self.wrap(root)
        self.dom.append(root)
        if root.nodeFlags() in libchrome.containerNodeFlags and self.proc_as.is_valid_address(
                root.firstChild):  # container
            self.parseDOMTree(root.firstChild.dereference())
        if self.proc_as.is_valid_address(root.next):  # not container
            self.parseDOMTree(root.next.dereference())
        return

class _node(obj.CType):
    def nodeFlags(self):
        return self.m_nodeFlags

    @property
    def previous(self):
        return self.m_previous

    @property
    def next(self):
        return self.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.m_parentOrShadowHostNode

    @property
    def tagName(self):
        return "unknown node"

    def printNode(self):
	print "Node tag: {0}\nMemory offset: 0x{1:08x}\n".format(
		self.tagName,
		self.obj_offset)

class _element_mixin():
    def nodeFlags(self):
        return self.Element.Container.Node.m_nodeFlags

    @property
    def previous(self):
        return self.Element.Container.Node.m_previous

    @property
    def next(self):
        return self.Element.Container.Node.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.Element.Container.Node.m_parentOrShadowHostNode

    @property
    def firstChild(self):
        return self.Element.Container.m_firstChild

    @property
    def lastChild(self):
        return self.Element.Container.m_lastChild

    @property
    def tagName(self):
        return libchrome.get_qualified_string(self, self.Element.m_tagName)

    def get_attributes(self):
        attributes = dict()

        elementData_offset = self.Element.m_elementData.v()
        shareableElementData = obj.Object("ShareableElementData", vm=self.obj_vm, offset=elementData_offset)
        Attribute = shareableElementData.m_attribute
        while self.obj_vm.is_valid_address(Attribute.m_name.v()):
            m_name = libchrome.get_qualified_string(Attribute, Attribute.m_name)
            m_value = libchrome.get_chrome_string(Attribute, Attribute.m_value)
            attributes[m_name] = m_value
            Attribute = obj.Object("Attribute", vm=self.obj_vm, offset=Attribute.v()+Attribute.struct_size)
        return attributes

    def printNode(self):
	print "Node tag: {0}\nNode attributes: {1}\nMemory offset: 0x{2:08x}\n".format(
		self.tagName,
		self.get_attributes(),
		self.obj_offset)

class _element(obj.CType):
    def nodeFlags(self):
        return self.Container.Node.m_nodeFlags

    @property
    def previous(self):
        return self.Container.Node.m_previous

    @property
    def next(self):
        return self.Container.Node.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.Container.Node.m_parentOrShadowHostNode

    @property
    def firstChild(self):
        return self.Container.m_firstChild

    @property
    def lastChild(self):
        return self.Container.m_lastChild

    @property
    def tagName(self):
        return libchrome.get_qualified_string(self, self.m_tagName)

    def get_attributes(self):
        attributes = dict()

        elementData_offset = self.m_elementData.v()
        shareableElementData = obj.Object("ShareableElementData", vm=self.obj_vm, offset=elementData_offset)
        Attribute = shareableElementData.m_attribute
        while self.obj_vm.is_valid_address(Attribute.m_name.v()):
            m_name = libchrome.get_qualified_string(Attribute, Attribute.m_name)
            m_value = libchrome.get_chrome_string(Attribute, Attribute.m_value)
            attributes[m_name] = m_value
            Attribute = obj.Object("Attribute", vm=self.obj_vm, offset=Attribute.v()+Attribute.struct_size)
        return attributes

    def printNode(self):
	print "Node tag: {0}\nNode attributes: {1}\nMemory offset: 0x{2:08x}\n".format(
		self.tagName,
		self.get_attributes(),
		self.obj_offset)


class _html_element_form(_element_mixin, obj.CType):
    @property
    def method(self):
        return self.m_method

    @property
    def action(self):
        return self.m_action


class _html_iframe_element(_element_mixin, obj.CType):
    @property
    def src(self):
        return self.m_URL

    @property
    def contentDocument(self):
        return self.m_contentFrame.m_domWindow.m_document.dereference()

    def printNode(self):
	print "Node tag: {0}\nNode attributes: {1}\nsrc: {2}\nMemory offset: 0x{3:08x}\nContained document offset: 0x{4:08x}\n".format(
		self.tagName,
		self.get_attributes(),
		libchrome.get_chrome_string(self, self.src),
		self.obj_offset,
		self.contentDocument)

class _html_anchor_element(_element_mixin, obj.CType):
    def href(self):
        attributes = self.get_attributes()
        return attributes["href"] if "href" in attributes.keys() else None


class _attributes(obj.CType):
    @property
    def getValue(self):
        return libchrome.get_chrome_string(self, self.m_value)

class _textNode(obj.CType):
    def nodeFlags(self):
        return self.Node.m_nodeFlags

    @property
    def previous(self):
        return self.Node.m_previous

    @property
    def next(self):
        return self.Node.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.Node.m_parentOrShadowHostNode

    @property
    def data(self):
        return self.m_data

    @property
    def tagName(self):
        return "Text"

    def printNode(self):
	print "Node tag: {0}\nContent: {1}\n".format(
		self.tagName,
		libchrome.get_chrome_string(self, self.data))


class _document(obj.CType):
    @property
    def url_string(self):
        url_string = libchrome.get_chrome_string(self, self.m_url)
        return url_string

    @property
    def title(self):
        title = libchrome.get_chrome_string(self, self.m_title)
        return title

    def is_valid(self):
        # debug.info("Document validation")
        if self.m_domWindow.m_document.v() == self.obj_offset:
            return True
        return False

    @property
    def documentElement(self):
        return self.m_documentElement


class ChromeTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(libchrome.chrome_vtypes)
        profile.object_classes.update(
            {"chrome_document": _document, "TextNode": _textNode, "Element": _element,
             "DOMNode": _node, "HTMLElementForm": _html_element_form, "HTMLIframeElement": _html_iframe_element, "HTMLAnchorElement": _html_anchor_element, "Attribute": _attributes})


class chrome_ragamuffin(common.AbstractWindowsCommand):
    """Recover some useful artifact from Chrome process memory"""
    urlparsed = []

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='str')
        config.add_option('documents', default=None,
                          help='Blink::Document\'s offsets (comma separated values)',
                          action='store', type='str')
	config.add_option('dom', default=None,
			  help='DOM root node offset. This will dump the DOM tree (use it only with -p option)',
			  action='store', type='str')

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)

        for task in tasks:
            proc_name = task.ImageFileName
            proc_pid = task.UniqueProcessId
            proc_as = task.get_process_address_space()

            # In cases when mm is an invalid pointer
            if not proc_as:
                continue

            # We scan just chrome instances
            if str(proc_name) != "chrome.exe":
                continue

            if "pid" in self._config.opts and str(proc_pid) != str(self._config.opts["pid"]):
                continue

            debug.info("Running on process PID %d PROC_NAME %s" % (proc_pid, proc_name))

            document_pointers = []
	    document = None
            if "documents" in self._config.opts:
                document_pointers = [int(p, 16) for p in self._config.opts["documents"].split(',')]
            else:
                for document_offset in DocumentScanner().scan(proc_as):
                    document_pointers.append(document_offset)

            for document_pointer in document_pointers:
                if proc_as.is_valid_address(document_pointer):
                    document_tmp = obj.Object("chrome_document", vm=proc_as, offset=document_pointer)
                    if document_tmp.is_valid():
			document = document_tmp
	    DOM = None
	    if "dom" in self._config.opts and "pid" in self._config.opts:
		rootNode = int(self._config.opts["dom"], 16)
		if proc_as.is_valid_address(rootNode):
			DOMTreeParser = DOMScanner(rootNode, proc_as)
			DOM = DOMTreeParser.scan()
            yield proc_pid, document, DOM


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"),
                                  ("Document offset", "20"),
                                  ("URL", "50"),
                                  ("Title", "50"),
                                  ("DOM start address", "8")])
        for pid, document, DOM in data:
	  if document is not None:
            self.table_row(outfd, pid, hex(document.obj_offset), str(document.url_string), str(document.title), hex(document.documentElement.v())[:-1])
	if DOM is not None:
	   for node in DOM:
	     node.printNode()

    def render_dot(self, outfd, data):
        for pid, document, DOM in data:
            outfd.write("/" + "*" * 72 + "/\n")
            outfd.write("/* Pid: {0:6}, url: {1} */\n".format(pid, str(document.url_string)))
            outfd.write("digraph DOMTree {\n")
            outfd.write("graph [rankdir = \"TB\"];\n")
            for node in DOM:
                fillcolor = "white"
                if node:
                    if node.parentOrShadowHostNode:
                        outfd.write(
                            "node_{0:08x} -> node_{1:08x}\n".format(
                                node.parentOrShadowHostNode.dereference().obj_offset or 0, node.obj_offset))
                        if node.tagName == "iframe":
                            fillcolor = "yellow"
                            outfd.write("node_{0:08x} [label = \"{{ {1}_0x{0:08x} | iframe document offset: 0x{3:08x} }}\" "
                                    "shape = \"record\" color = \"blue\" style = \"filled\" fillcolor = \"{2}\"];\n".format(
                            node.obj_offset,
                            node.tagName,
                            fillcolor,
                            node.contentDocument.v()))
                        else:
			    if node.tagName == "a":
				fillcolor = "red"
                            outfd.write("node_{0:08x} [label = \"{{ {1}_0x{0:08x} }}\" "
                                    "shape = \"record\" color = \"blue\" style = \"filled\" fillcolor = \"{2}\"];\n".format(
                            node.obj_offset,
                            node.tagName,
                            fillcolor))
            outfd.write("}\n")
