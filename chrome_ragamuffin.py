"""
@author:       Cube
"""
import inspect
import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.addrspace as addrspace
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid

chrome_vtypes = {
    'chrome_space': [56, {
      'heap': [24, ['pointer', ['void']]],
      'allocation_space': [32, ['int']],
      'executability': [36, ['int']]
    }],
    'chrome_isolate': [27712, {
      # A 32 inizia l'heap inline.
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
    'dom_element': [96, {
     'm_nodeFlags': [16, ['unsigned int']],
     'm_previous': [40, ['pointer',['dom_element']]],
     'm_next': [48, ['pointer', ['dom_element']]],
     'm_elementData': [88, ['pointer', ['void']]]
    }],
    'chrome_document': [2800, {
     'm_domWindow': [472, ['pointer', ['local_dom_window']]],
     'm_string': [600, ['pointer', ['stringimpl']]],
     'm_documentElement': [1208, ['pointer', ['dom_element']]],
     'm_title': [1392, ['pointer', ['stringimpl']]],
    }],
}

class _space(obj.CType):
  
  def is_valid(self):
    # verificare che il puntatore allo heap sia giusto.
    if (self.executability in [0,1] and
       self.allocation_space < 5 and
       self.allocation_space >= 0):
       return True
    return False

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

  def check_space(self, ob,allsp,exe):
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

class _document(obj.CType):
    
    def get_chrome_string(self, strimpl_offset):
        strimpl_object = obj.Object("stringimpl", vm=self.obj_vm, offset=strimpl_offset) #instanzia l'oggetto puntato da m_string (l'url vero e proprio)
        string_length = strimpl_object.m_length #lunghezza dell'url 
        #l url e' shiftato di 12 byte rispetto alla zona referenziata dal puntatore alla StringImpl. I primi 12 byte sono occupati da vari metadati, dopo parte la stringa.
        #Guardare la definizione del VType stringimpl per ulteriori dettagli
        raw_string = self.obj_vm.read(strimpl_offset + 12, string_length)            
        return raw_string
    
    @property
    def documentElement(self):
        return self.m_documentElement

    @property
    def url_string(self):
        url_string = self.get_chrome_string(self.m_string)
        return  (url_string[:50] + "...") if len(url_string) > 50 else url_string

    @property
    def document_title(self):
        title = self.get_chrome_string(self.m_title)
        return title

    def is_valid(self, proc_as):
        if self.m_domWindow.m_document.v() == self.obj_offset: #abbiamo un document?
            return True
        return False

class _domElement(obj.CType):
    
    @property
    def nodeFlags(self):
        return self.m_nodeFlags

    @property
    def elementData(self):
        return self.m_elementData

class ChromeTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(chrome_vtypes)
        profile.object_classes.update({"chrome_space": _space, "chrome_isolate": _isolate, "chrome_document": _document, "dom_element": _domElement})

class chrome_ragamuffin(linux_pslist.linux_pslist):
    """Recover some useful artifact from Chrome process memory"""

    def __init__(self, config, *args, **kwargs):
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

    def dom_tree_parser(self, proc_as, document, task):
        documentElement_ptr = document.documentElement
        documentElement = obj.Object("dom_element", vm=proc_as, offset=documentElement_ptr)
        
    def html_document_entries(self, proc_as, task):
        url_parsed_signatures = [struct.pack("<iiiiiii", 0, 4, 0, -1, 0, -1, 7), struct.pack("<iiiiiii", 0, 5, 0, -1, 0, -1, 8), struct.pack("<iiiiiii", 0, -1, 0, -1, 0, -1, 0)]
        for(idx, m_parsed_ptr) in enumerate(task.search_process_memory(url_parsed_signatures, heap_only = False)):
        #ho una possibile struct url::Parsed
            ptr = m_parsed_ptr - 528
            document = obj.Object("chrome_document", vm=proc_as, offset=ptr)
            if document.is_valid(proc_as):
                yield task, ptr, document.url_string, document.document_title


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

            #if task.pid != 2308:
                #continue
            
            #for (task, ptr) in (self.isolate_spaces_heap_entries(proc_as, task)): #trovo puntatori allo heap, all'isolate e agli spaces
            for (task, ptr, url, title) in (self.html_document_entries(proc_as, task)): #trovo puntatori ai Document
                yield task, ptr, url, title
            

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Document offset", str),
                         ("URL", str),
                         ("Title", str)],
                        self.generator(data))

    def generator(self, data):
        for task, offs, url, title in data:
            yield (0, [int(task.pid), hex(offs), str(url), str(title)])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "8"),
                                  ("Document offset", "20"),
                                  ("URL", "50"),
                                  ("Title", "50")])

        for task, offs, url, title in data:
            self.table_row(outfd, task.pid, hex(offs), str(url), str(title))
