# Chrome Ragamuffin
Volatility plugin designed to extract useful information from Google Chrome's address space.

The goal of this plugin is to make possible the analysis of a Google Chrome running instance. Starting from a memory dump, 
Chrome Ragamuffin can list which page was open on which tab and it is able to extract the DOM Tree in order to analyze the full page structure.

At this time, Chrome Ragamuffin can scan for *blink::Document* objects in memory and extract their DOM tree. The tree can be rendered either in text (giving an in-depth overview of the nodes structure) and dot (giving a hierarchical overview of the tree) mode.

In addition, we are able to get several details (visited URLs, redirect chain, method of request, iframe/form showed during the navigation etc.) about the user navigation without any limitation introduced by the incognito mode.

## Requirements and dependencies
Chrome Ragamuffin is shipped with libchrome_*$browserrelease*.py libraries. These libraries contain the data structures (VTypes) corrisponding to their respective Google Chrome objects. If you need to run Chrome Ragamuffin against particular *$browserrelease*, please download the library that match it.
### Features list
- [x] Little endian support
- [x] DOM Analysis
- [x] Active HTML Documents overview
- [x] Google Chrome (64-bit) Windows support
- [x] History Extraction from the Browser Process
- [ ] In-memory cache analysis
- [ ] JavaScript execution analysis
- [ ] HTTP requests/responses analysis
- [ ] Big endian support
- [ ] Google Chrome (32-bit) Windows support
- [ ] Chromium (32/64 bit) Linux/macOS support

Chrome Ragamuffin -h:

```sh
  -p PID, --pid=PID     Operate on this Process ID
  --documents=DOCUMENTS Blink::Document's offsets (comma separated values)
  --dom=DOM             DOM root node offset. This will dump the DOM tree
  --whatsapp=WHATSAPP   get sidebar and main active chat from a renderer process
  --analysis=ANALYSIS   you have to choose between "history" (history navigation from browser process) and "renderer" (document objects from the renderer process)

Module Output Options: csv, dot, text
```

## Analysis modes
We can switch the analysis mode using the *--analysis* flag. At the moment, we have two options to use with this flag: *renderer* and *history*.

1) *history* flag:
this mode is designed to extract the entire user navigation. We'll gain information either from a normal or an incognito navigation. You can render the output in its text and csv notation. We strongly suggest to render it in csv format, because of the huge amount of data displayed.
With this mode, aside from the visited pages, you'll gather details about the iframe and submitted form too.

2) *renderer* flag:
search for *blink::Document* object in memory and display them. In addition, you can extend the analysis extracting the Document Object Model from a document object.
You can get the output in two different modes using the *--output* flag. (examples below).

## Examples
1) **HISTORY**

Extract the whole history navigation:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump1.vmem chrome_ragamuffin --anaysis history

Volatility Foundation Volatility Framework 2.6
| ID | Offset         | Title                                     | User typed url                            | Original request url                      | Status code | Method | Post params   | Transition                                           | Referer                                | Redirect chain                          | UTC Timestamp       | Restore type           | Type page        |
|----|----------------|-------------------------------------------|-------------------------------------------|-------------------------------------------|-------------|--------|---------------|------------------------------------------------------|----------------------------------------|-----------------------------------------|---------------------|------------------------|------------------|
| 22 | 0x1a224d1d600  | file:///C:/Users/cube/Documents/test.html | file:///C:/Users/cube/Documents/test.html | file:///C:/Users/cube/Documents/test.html | 0           | GET    | 0             | Reload page, session restore or undo close tab       | None                                   | data:text/html,chromewebdata            | 21/09/2017 08.40.22 | LAST_SESSION_CRASHED   | ERROR            |
| 32 | 0x1a228691300  | None                                      | http://192.168.1.124/index.html           | http://192.168.1.124/index.html           | 200         | GET    | 200           | User used the address bar to trigger this navigation | None                                   | http://192.168.1.124/index.html         | 21/09/2017 09.14.28 | Entry was not restored | NORMAL           |
| 32 | 0x1a2288d8cb0L | frame_entry_object                        | http://mybank.com/changepassword.php      | http://mybank.com/changepassword.php      | None        | POST   | 0x1a2288d8e20 | None                                                 | http://192.168.1.124/hghrueguoeir.html | http://192.168.1.124/changepassword.php | 21/09/2017 09.14.28 | None                   | framePath frame0 |
```

The example above shows a semplified sample of a CSRF (Cross-Site Request Forgery) attack a user has been involved in (https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)). The id 32 navigation started with a GET request. The user *used the address bar to trigger the navigation* and typed the following URL: *http://192.168.1.124/index.html*. Within the same navigation ID (32), we can found another entry which corresponds to an <iframe> (*framePath frame0*) element contained in the *index.html* page. This iframe is displaying the webpage at the *http://192.168.1.124/changepassword.php* URL and it was reached by a POST request from the *http://192.168.1.124/hghrueguoeir.html* URL (the *referer*). Using the *volshell* we can extract the information related to the submitted form which started out the POST request, dumping out the PageState object at the *Post params* address (0x1a2288d8e20):

```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump.vmem volshell --offset 0xffffd08754ae5780

In [1]: p = proc()

In [2]: proc_as = p.get_process_address_space()

In [3]: frame_entry = obj.Object("FrameNavigationEntry", vm=proc_as, offset=0x1a2288d8cb0) #offset field 

In [4]: frame_entry.dump_page_state()
Out[4]: '\xac\x01..\x19.......N...h.t.t.p.:././.1.9.2...1.6.8...1...1.2.4./.c.h.a.n.g.e.p.a.s.s.w.o.r.d...p.h.p...@...<.!.-.-.f.r.a.m.e.P.a.t.h. ././.<.!.-.-.f.r.a.m.e.0.-.-.>.-.-.>.....L...h.t.t.p.:././.1.9.2...1.6.8...1...1.2.4./.h.g.h.r.u.e.g.u.o.e.i.r...h.t.m.l.....\xab\x02\x07\x85\xafY\x05.\xac\x02\x07\x85\xafY\x05.\x02...........\x01...\x01.......-...**new_username**=username&**new_password=qwerty1345**...\x0e\xb8\x07\x85\xafY\x05.....B...a.p.p.l.i.c.a.t.i.o.n./.x.-.w.w.w.-.f.o.r.m.-.u.r.l.e.n.c.o.d.e.d.......'
```

This object reperesents some frame object's serialized information:
* **h.t.t.p.:././.1.9.2...1.6.8...1...1.2.4./.c.h.a.n.g.e.p.a.s.s.w.o.r.d...p.h.p** is the value of the *action* value of the form
* **new_username=username&new_password=qwerty1345** are the form fields
* **a.p.p.l.i.c.a.t.i.o.n./.x.-.w.w.w.-.f.o.r.m.-.u.r.l.e.n.c.o.d.e.d** is the mime-type of the form

To sum up, the user visited a web page (http://192.168.1.124/index.html) which contained an iframe (with src=http://192.168.1.124/hghrueguoeir.html). In the iframe, a POST request was submitted on http://mybank.com/changepassword.php web site with **username** and **password** form fields (new_username=username&new_password=qwerty1345).

2) **RENDERER**

Extract all available *blink::Document* objects in memory with their respective memory offset:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump2.vmem chrome_ragamuffin --analysis renderer

Volatility Foundation Volatility Framework 2.6
Pid      Document offset      URL                                                Title                                              DOM start address
-------- -------------------- -------------------------------------------------- -------------------------------------------------- -----------------
    4384 0x3f8c0aa25a0        https://truel.it/                                  TRUEL IT | Home                                    0x3f8c0aa3230   
    3184 0x34da48225a0        https://www.google.it/                             Google                                             0x34da4823230   
    3948 0x35c2ff825a0        https://twitter.com/                               Twitter. ? ci? che sta accadendo.                  0x35c2ff83230   
    3948 0x35c2ffc1838        https://twitter.com/i/vi...&player_id=1&rpc_init=1 Twitter web player                                 0x35c2ffc30f8   
    3948 0x35c2ffc2468        https://twitter.com/i/vi...&player_id=0&rpc_init=1 Twitter web player                                 0x35c2ffc9b98   
    3948 0x35c2ffe1838        about:blank                                        None                                               0x35c2ffe2468   
    3948 0x35c2ffe4260        about:blank                                        None                                               0x35c2ffe4e90   
    3948 0x35c2ffea3e0        about:blank                                        None                                               0x35c2ffeb010  
    3948 0x35c2ffec050        about:blank                                        None                                               0x35c2ffecc80   
    3948 0x35c30003ec0        about:blank                                        None                                               0x35c30004af0   
    3948 0x35c30009048        about:blank                                        None                                               0x35c30009c78   
    3948 0x35c30013ce8        about:blank                                        None                                               0x35c30014918   
    3948 0x35c3001d810        https://twitter.com/push_service_worker.js         None                                               0x35c3001e440   
    3588 0x4d67092f220        https://app.tutanota.com/#box                      vulwdfhvl@tuta.io - Tutanota                       0x4d67092fff0   
     540 0x3b7f3d225a0        http://192.168.1.135/econom.html                   None                                               0x3b7f3d231d0   
     540 0x3b7f3d261d0        data:text/html,chromewebdata                       138.68.93.144                                      0x3b7f3d26e60   
```
Every line in the table corresponds to a WebKit's *blink::Document* object, which describes the active HTML document rendered in a browser tab.
These information makes us able to gain an overview of the data we're going to examine in details in the next steps. For each *Document*, Chrome Ragamuffin returns the memory offset (Document offset) and the virtual address of the first DOM element (*html* tag). The *URL* and *Title* fields show us the URL of the *Document* and the *title* tag content rispectively. At last, every tab in Google Chrome is a separate thread and every object is associated to its tab PID.

Extract the DOM Tree in dot language of a document:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump2.vmem chrome_ragamuffin -p 540 --analysis renderer --documents 0x3b7f3d225a0 --dom 0x3b7f3d231d0 --output dot --output-file econom.dot
```
- http://192.168.1.135/econom.html:
![DOT DOM Tree](https://github.com/MalfurionStormrage/chrome_ragamuffin/blob/master/540.png)

Print the DOM Tree in text mode:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump2.vmem chrome_ragamuffin -p 540 --analysis renderer --documents 0x3b7f3d225a0 --dom 0x3b7f3d231d0
Volatility Foundation Volatility Framework 2.6
Node tag: html
Node attributes: {}
Memory offset: 0x3b7f3d231d0

Node tag: head
Node attributes: {}
Memory offset: 0x3b7f3d23238

Node tag: title
Node attributes: {}
Memory offset: 0x3b7f3d232a0

[...]

Node tag: img
Node attributes: {'src': './img.jpg'}
Memory offset: 0x3b7f3d23640

[..]

Node tag: iframe
Node attributes: {}
src: ./page.html
Memory offset: 0x3b7f3d237c8
Contained document offset: 0x3b7f3d261d0

Node tag: Text
Content: 

Node tag: h3
Node attributes: {}
Memory offset: 0x3b7f3d246d0

Node tag: Text
Content: YOU WON A LOT OF MONEY!

[...]
```

## Analysis with *volshell* plugin:
Below, we went through the DOM elements using the *volshell* plugin. With its help we can perform a targeted analysis on DOM's elements that we are interested in.

Get DOM Tree:

```sh
In [4]: document = obj.Object("chrome_document", vm=proc_as, offset=0x3b7f3d225a0)
In [5]: dom = chrome_ragamuffin.DOMScanner(document.documentElement, proc_as).scan()

In [6]: dom
Out[6]: 
[[_element Element] @ 0x3B7F3D231D0,
 [_element Element] @ 0x3B7F3D23238,
 [_element Element] @ 0x3B7F3D232A0,
 [_textNode TextNode] @ 0x3B7F3D23310,
 [_element Element] @ 0x3B7F3D23360,
 [_textNode TextNode] @ 0x3B7F3D233C8,
 [_element Element] @ 0x3B7F3D23418,
 [_textNode TextNode] @ 0x3B7F3D23480,
 [_element Element] @ 0x3B7F3D234D0,
 [_textNode TextNode] @ 0x3B7F3D23538,
 [_element Element] @ 0x3B7F3D23588,
 [_textNode TextNode] @ 0x3B7F3D235F0,
 [_element Element] @ 0x3B7F3D23640,
 [_element Element] @ 0x3B7F3D23710,
 [_textNode TextNode] @ 0x3B7F3D23778,
 [_html_iframe_element HTMLIframeElement] @ 0x3B7F3D237C8,
 [_textNode TextNode] @ 0x3B7F3D24680,
 [_element Element] @ 0x3B7F3D246D0,
 [_textNode TextNode] @ 0x3B7F3D24738,
 [_textNode TextNode] @ 0x3B7F3D24788,
 [_textNode TextNode] @ 0x3B7F3D247D8]
```
Search for iframe nodes:
```sh
In [8]: iframe = [x for x in dom if x.tagName == "iframe"]
In [13]: dt(iframe[0])
[_html_iframe_element HTMLIframeElement] @ 0x3B7F3D237C8
0x0   : Element                        4088604538824
0x70  : m_contentFrame                 2124868027416
0x98  : m_URL
```
Get the page contained in the iframe:
```sh
In [14]: page_contained = iframe[0].contentDocument
In [15]: page_contained
Out[15]: [_document m_document] @ 0x3B7F3D261D0
In [16]: page_contained.title
Out[16]: '138.68.93.144'
In [17]: page_contained.url_string
Out[17]: 'data:text/html,chromewebdata'
```
