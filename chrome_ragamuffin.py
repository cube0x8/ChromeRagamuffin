# Copyright (C) 2017 Alessandro De Vito (@Cube)
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
@author: Alessandro De Vito (@Cube)
@license: GNU General Public License 2.0 or later
"""

import inspect
import libchrome
import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.scan as scan
import volatility.utils as utils
from volatility.renderers import TreeGrid
import time

document_list = []
urlparsed = []

class UrlParsedScanner():
    task = None
    proc_as = None

    def __init__(self, address_space, task):
        self.task = task
        self.proc_as = address_space

    def scan(self):
        for(idx, m_parsed_ptr) in enumerate(self.task.search_process_memory(libchrome.url_parsed_signatures, heap_only = False)):
        #maybe a url::Parsed struct found. save it
            urlparsed.append(m_parsed_ptr)
        
class DocumentScanner():
    proc_as = None

    def __init__(self, address_space):
        self.proc_as = address_space

    def scan(self):
        for(m_parsed_ptr) in urlparsed:
            #document start offset
            document_start_offset = m_parsed_ptr - 528
            document = obj.Object("chrome_document", vm=self.proc_as, offset=document_start_offset)
            if self.is_valid(document):
                document_list.append(document_start_offset)
                yield document_start_offset, document.url_string, document.document_title

    def is_valid(self, document):
        if document.m_domWindow.m_document.v() == document.obj_offset: #mutual-reference Document <-> LocalDomWindow
            return True
        return False

class V8Scanner():
    proc_as = None
    task = None

    def __init__(self, address_space, task):
        self.proc_as = address_space
        self.task = task

    def scan(self):
        for (idx, codespace_ptr) in enumerate(self.task.search_process_memory([struct.pack('<II', 2, 1)], heap_only = False)):
        #maybe NewSpace
            space = obj.Object("chrome_space", vm=self.proc_as, offset=codespace_ptr - 32)
            heap = obj.Object("v8_heap", vm=self.proc_as, offset=space.heap)
            if self.is_valid(heap):
                isolate = obj.Object("chrome_isolate", vm=self.proc_as, offset=heap.isolate_)
                yield isolate.obj_offset

    def is_valid(self, heap):
        isolate = heap.isolate_.dereference()
        if isolate.obj_offset == isolate.isolate_:
            return True

class _treeScope(obj.CType):
    def is_valid(self, document):
        parentTreeScope = self.m_parentTreeScope
        if parentTreeScope.m_document.v() == document:
            return True
        return False

class _domElement(obj.CType):
    def is_valid(self):
        if self.m_treescope.m_document.v() in document_list and self.m_parentOrShadowHostNode.m_nodeFlags == 5148:
            return True
        return False

    @property
    def characters(self):
        return libchrome.get_chrome_string(self, self.m_data)

    @property
    def firstChild(self):
        return self.m_firstChild

class _resource(obj.CType):
    def is_valid(self):
        if self.m_type == 3 and self.m_status == 2:
            return True
        return False
    
    @property
    def plain_js(self):
        script_buffer = obj.Object("js_buffer", vm=self.obj_vm, offset=self.script_buffer)
        return libchrome.get_chrome_string(self, script_buffer.m_script)

class _document(obj.CType):
    @property
    def documentElement(self):
        return self.m_documentElement

    @property
    def url_string(self):
        url_string = libchrome.get_chrome_string(self, self.m_url)
        return url_string

    @property
    def document_title(self):
        title = libchrome.get_chrome_string(self, self.m_title)
        return title

class ChromeTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(libchrome.chrome_vtypes)
        profile.object_classes.update({"chrome_document": _document, "resource": _resource, "treescope": _treeScope, "dom_element": _domElement, "htmlscriptelement": _domElement})

class chrome_ragamuffin(linux_pslist.linux_pslist):
    """Recover some useful artifact from Chrome process memory"""
    urlparsed = []

    def __init__(self, config, *args, **kwargs):
        config.add_option("dump")
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
    
    def rummage_javascript(self, proc_as, task):
        #JavaScript beetween <script> and </script> tags
        Text_nodeFlags = 5122
        
        for (idx, element) in enumerate(task.search_process_memory([struct.pack("<Q", Text_nodeFlags)], heap_only=False)):
            htmlscriptelement = obj.Object("dom_element", vm=proc_as, offset=element-16)
            if htmlscriptelement.is_valid():
                #print("element start offset: %s" % (hex(proc_as.vtop(element - 16))))
                print htmlscriptelement.characters

        #external JavaScript included with "src".
        for m_parsed_ptr in self.urlparsed:
            m_preloadResults_offset = m_parsed_ptr - 88
            resource = obj.Object("resource", vm=proc_as, offset=m_preloadResults_offset)
            if resource.is_valid():
                print resource.plain_js
                yield resource.plain_js

    def calculate(self):
        linux_common.set_plugin_members(self)

        tasks = linux_pslist.linux_pslist(self._config).calculate()
    
        for task in tasks:
            proc_as = task.get_process_address_space()

            # In cases when mm is an invalid pointer
            if not proc_as:
                continue

            # We scan just chrome instances
            if  str(task.comm) != "chrome":
                continue

            if "pid" in self._config.opts and str(task.pid) != str(self._config.opts["pid"]):
                continue

            UrlParsedScanner(proc_as, task).scan()

            for (document_offset, url, title) in DocumentScanner(proc_as).scan():
                yield task, document_offset, url, title

            #for isolate_ptr in V8Scanner(proc_as, task).scan():
                #print task.pid, isolate_ptr

            if "dump" in self._config.opts:
                for js in (self.rummage_javascript(proc_as, task)):
                    continue

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Document offset", str),
                         ("URL", str),
                         ("Title", str)],
                        self.generator(data))

    def generator(self, data):
        for task, ptr, url, title, n_js, js_list in data:
            yield (0, [int(task), str(ptr), str(url), str(title)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"),
                                  ("Document offset", "20"),
                                  ("URL", "50"),
                                  ("Title", "50")])

        for task, offs, url, title in data:
            self.table_row(outfd, task.pid, hex(offs), str(url), str(title))
