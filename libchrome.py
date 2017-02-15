import struct
import volatility.obj as obj

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
     'm_nodeFlags': [16, ['unsigned int']],
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

# url::Parsed signatures. Rispectively: http, file, https, no_schema
url_parsed_signatures = [struct.pack("<iiiiiii", 0, 4, 0, -1, 0, -1, 7), 
                         struct.pack("<iiiiiiiiiii", 0, 4, 0, -1, 0, -1, 0, -1, 0, -1, 7), 
                         struct.pack("<iiiiiii", 0, 5, 0, -1, 0, -1, 8), 
                         struct.pack("<iiiiiii", 0, -1, 0, -1, 0, -1, 0)]

#https://docs.google.com/document/d/1kOCUlJdh2WJMJGDf-WoEQhmnjKLaOYRbiHz5TiGJl14/edit
def get_chrome_string(self, strimpl_offset):
        strimpl_object = obj.Object("stringimpl", vm=self.obj_vm, offset=strimpl_offset)
        string_length = strimpl_object.m_length 
        if string_length > 0:
            raw_string = self.obj_vm.read(strimpl_offset + 12, string_length)            
            return raw_string
        return None


