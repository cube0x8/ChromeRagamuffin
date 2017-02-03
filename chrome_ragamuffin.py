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
import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
import pprint

chrome_vtypes = {
    'chrome_space': [56, {
      'heap': [24, ['pointer', ['void']]],
      'allocation_space': [32, ['int']],
      'executability': [36, ['int']]
    }],
    'chrome_isolate': [27712, {
      # We have the Heap at the offset 32.
      'heap_isolate_ptr': [48, ['pointer', ['chrome_isolate']]],
      'newspace': [3072, ['chrome_space']],
      'oldspace': [4152, ['pointer', ['chrome_space']]],
      'codespace': [4160, ['pointer', ['chrome_space']]],
      'mapspace': [4168, ['pointer', ['chrome_space']]],
      'lospace': [4176, ['pointer', ['chrome_space']]],
    }],
    'stringimpl': [12, {
     'm_refCount': [0, ['unsigned int']],
     'm_length': [4, ['unsigned int']],
     'm_hash': [8, ['BitField', dict(start_bit = 0, end_bit = 23, native_type="unsigned int")]],
     'm_isAtomic': [11, ['BitField', dict(start_bit=0, end_bit=0, native_type="unsigned int")]],
     'm_is8bit': [11, ['BitField', dict(start_bit=1, end_bit=1, native_type="unsigned int")]],
     'm_isStatic': [11, ['BitField', dict(start_bit=2, end_bit=2, native_type="unsigned int")]],
    }],
    'local_dom_window': [384, {
      'm_document':[192, ['pointer', ['chrome_document']]],
    }],
    'dom_element': [72, {
     'm_nodeFlags': [16, ['unsigned int']],
     'm_parentOrShadowHostNode': [24, ['pointer', ['dom_element']]],
     'm_treescope': [32, ["pointer", ["treescope"]]],
     'm_previous': [40, ['pointer',['dom_element']]],
     'm_next': [48, ['pointer', ['dom_element']]],
     'm_data': [64, ['pointer', ['stringimpl']]]
    }],
    'htmlscriptelement': [112, {
     'm_nodeFlags': [16, ['unsigned int']],
     'm_treescope': [32, ["pointer", ["treescope"]]],
     'm_previous': [40, ['pointer',['dom_element']]],
     'm_next': [48, ['pointer', ['dom_element']]],
     'm_firstChild': [72, ['pointer', ['dom_element']]]
    }],
   'chrome_document': [2800, {
     'm_domWindow': [472, ['pointer', ['local_dom_window']]],
     'm_url': [600, ['pointer', ['stringimpl']]],
     'm_documentElement': [1208, ['pointer', ['dom_element']]],
     'm_title': [1392, ['pointer', ['stringimpl']]],
     'm_scriptRunner': [1544, ['pointer', ['ScriptRunner']]],
    }],
    'resource': [1856, {
     'remoteIPAddress': [1520, ['pointer', ['stringimpl']]],
     'm_data': [1800, ["pointer", ["void"]]],
     'm_type': [1776, ['BitField', dict(start_bit=2, end_bit=5, native_type="unsigned int")]],
     'm_status': [1776, ['BitField', dict(start_bit=6, end_bit=8, native_type="unsigned int")]],
     'script_buffer': [1840, ['pointer', ['js_buffer']]]
    }],
    'js_buffer':[32, {
     'm_script': [24, ['pointer', ['stringimpl']]],
    }],
    'treescope': [88, {
     'm_document': [16, ['pointer', ["chrome_document"]]],
     'm_parentTreeScope': [24, ['pointer', ["treescope"]]]
    }],
}

document_list = []

def get_chrome_string(self, strimpl_offset):
        strimpl_object = obj.Object("stringimpl", vm=self.obj_vm, offset=strimpl_offset) #instanzia l'oggetto puntato da m_string (l'url vero e proprio)
        string_length = strimpl_object.m_length 
        #l url e' shiftato di 12 byte rispetto alla zona referenziata dal puntatore alla StringImpl. I primi 12 byte sono occupati da vari metadati, dopo parte la stringa.
        #Guardare la definizione del VType stringimpl per ulteriori dettagli
        if string_length > 0:
            raw_string = self.obj_vm.read(strimpl_offset + 12, string_length)            
            return raw_string
        return None
    

class _space(obj.CType):
  
  def is_valid(self):
    # verificare che il puntatore allo heap sia giusto.
    if (self.executability in [0,1] and
       self.allocation_space < 5 and
       self.allocation_space >= 0):
       return True
    return False

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
        return get_chrome_string(self, self.m_data)

    @property
    def firstChild(self):
        return self.m_firstChild


class _isolate(obj.CType):
  def is_valid(self):
    toreturn = True
    if not self.check_space(self.newspace, 0,0):
      self.debug_fail()
      toreturn = False
    if not self.check_space(self.oldspace.dereference(), 1,0):
      self.debug_fail()
      toreturn = False
    if not self.check_space(self.codespace.dereference(), 2,1):
      self.debug_fail()
      toreturn = False
    if not self.check_space(self.mapspace.dereference(), 3,0):
      self.debug_fail()
      toreturn = False
    if not self.check_space(self.lospace.dereference(), 4,0):
      self.debug_fail()
      toreturn = False
    if self.heap_isolate_ptr.v() != self.obj_offset:
      self.debug_fail()
      toreturn = False
    return toreturn

  def check_space(self, ob, allsp, exe):
    toreturn = True
    if not ob.is_valid():
      self.debug_fail()
      toreturn = False
    if ob.executability !=exe or ob.allocation_space != allsp:
      self.debug_fail()
      toreturn = False
    if ob.heap.v() != self.obj_offset +32:
      self.debug_fail()
      toreturn = False
    return toreturn
    
  def debug_fail(self):
      callerframerecord = inspect.stack()[1]    # 0 represents this line
                                            # 1 represents line at caller
      frame = callerframerecord[0]
      info = inspect.getframeinfo(frame)
      print "%r: %s:%d" % (self.obj_offset, info.function, info.lineno)

class _resource(obj.CType):
    def is_valid(self):
        if self.m_type == 3 and self.m_status == 2:
            return True
        return False
    
    @property
    def plain_js(self):
        script_buffer = obj.Object("js_buffer", vm=self.obj_vm, offset=self.script_buffer)
        return get_chrome_string(self, script_buffer.m_script)

class _document(obj.CType):
    
    @property
    def documentElement(self):
        return self.m_documentElement

    @property
    def url_string(self):
        url_string = get_chrome_string(self, self.m_url)
        return url_string

    @property
    def document_title(self):
        title = get_chrome_string(self, self.m_title)
        return title

    def is_valid(self, proc_as):
        if self.m_domWindow.m_document.v() == self.obj_offset: #abbiamo un document?
            return True
        return False

class ChromeTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(chrome_vtypes)
        profile.object_classes.update({"chrome_space": _space, "chrome_isolate": _isolate, "chrome_document": _document, "resource": _resource, "treescope": _treeScope, "dom_element": _domElement, "htmlscriptelement": _domElement})

class chrome_ragamuffin(linux_pslist.linux_pslist):
    """Recover some useful artifact from Chrome process memory"""
    urlparsed = []

    def __init__(self, config, *args, **kwargs):
        config.add_option("dump_resource")
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
    
    def isolate_spaces_heap_entries(self, proc_as, task):
        spaces = []

        for (idx, code_ptr) in enumerate(task.search_process_memory([struct.pack('<II', 2,1)], heap_only = False)):
        #ho l'inizio di un possibile code_space
            spaces.append(struct.pack("<Q", code_ptr - 32))

        for (idx, isol_code_ptr) in enumerate(task.search_process_memory(spaces, heap_only = False)):
        #ho un puntatore ad un puntatore di possibile code_space. Quindi potrei essere in un Isolate
            ptr = isol_code_ptr - 4160 #ottengo puntatore all'inizio di un possibile isolate
            isol = obj.Object("chrome_isolate", vm=proc_as, offset=ptr) #creo un VTypes per l'Isolate
            if isol.is_valid(): #elimina i falsi positivi. Verifico che il Vtypes creato sia valido.
                yield task,ptr

    def rummage_javascript(self, proc_as, task):
        #JavaScript beetween <script> and </script> tags
        Text_nodeFlags = 5122
        
        for (idx, element) in enumerate(task.search_process_memory([struct.pack("<Q", Text_nodeFlags)], heap_only=False)):
            htmlscriptelement = obj.Object("dom_element", vm=proc_as, offset=element-16)
            if htmlscriptelement.is_valid():
                #print("element start offset: %s" % (hex(proc_as.vtop(element - 16))))
                print htmlscriptelement.characters

        #JavaScript shipped by HTTP request.
        for m_parsed_ptr in self.urlparsed:
            m_preloadResults_offset = m_parsed_ptr - 88
            resource = obj.Object("resource", vm=proc_as, offset=m_preloadResults_offset)
            if resource.is_valid():
                print resource.plain_js
                yield resource.plain_js

    def html_document_entries(self, proc_as, task):
        url_parsed_signatures = [struct.pack("<iiiiiii", 0, 4, 0, -1, 0, -1, 7), struct.pack("<iiiiiiiiiii", 0, 4, 0, -1, 0, -1, 0, -1, 0, -1, 7), struct.pack("<iiiiiii", 0, 5, 0, -1, 0, -1, 8), struct.pack("<iiiiiii", 0, -1, 0, -1, 0, -1, 0)]
        for(idx, m_parsed_ptr) in enumerate(task.search_process_memory(url_parsed_signatures, heap_only = False)):
        #maybe a url::Parsed struct found. save it
            self.urlparsed.append(m_parsed_ptr)
            #document start offset
            document_start_offset = m_parsed_ptr - 528
            document = obj.Object("chrome_document", vm=proc_as, offset=document_start_offset)
            if document.is_valid(proc_as):
                document_list.append(document_start_offset)
                
                yield task, document_start_offset, document.url_string, document.document_title


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

            #for (task, ptr) in (self.isolate_spaces_heap_entries(proc_as, task)): #trovo puntatori allo heap, all'isolate e agli spaces
            for (task, ptr, url, title) in (self.html_document_entries(proc_as, task)): #trovo puntatori ai Document
                yield task, ptr, url, title

            if "dump_resource" in self._config.opts:
                for js in (self.rummage_javascript(proc_as, task)): #dumpo i js
                    continue


    def unified_output(self, data):
        print len(data)
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

    def render_body(self, outfd, data):
        print "so what" 
