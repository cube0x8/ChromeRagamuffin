# Chrome Ragamuffin
Volatility plugins to extract some useful information from Google Chrome's address space.

The goal of this plugin is to make possible the analysis of a Google Chrome running instance. Starting from a memory dump, 
Chrome Ragamuffin can list which page was open on which tab and it is able to extract the DOM Tree in order to analyze the full page structure.

At this time, Chrome Ragamuffin can scan for *blink::Document* objects in memory and extract their DOM tree. The tree can be rendered either in text (giving an in-depth overview of the nodes structure) and dot (giving a hierarchical overview of the tree) mode.

## Requirements and dependencies
Chrome Ragamuffin is shipped with libchrome_*$browserrelease*.py libraries. These libraries contain the data structures (VTypes) corrisponding to their respective Google Chrome objects. If you need to run Chrome Ragamuffin against particular *$browserrelease*, please download the library that match it.
### Features list
- [x] Little endian support
- [x] DOM Analysis
- [x] Active HTML Documents overview
- [x] Google Chrome (64-bit) on Windows OSes
- [ ] JavaScript execution analysis
- [ ] HTTP requests/responses analysis
- [ ] Big endian support
- [ ] Google Chrome (32-bit) on Windows OSes
- [ ] Chromium (64-bit) on Linux OSes
- [ ] Chromium (32-bit) on Linux OSes

## Examples:
1) Extract all available *blink::Document* objects in memory with their respective memory offset:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump.vmem chrome_ragamuffin

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
Every line in the table corresponding to a WebKit's *blink::Document* object, which describes an active HTML document in a browser tab.
These informations makes us able to gain an overview of the data we're going to examine in details in the next steps. For each *Document*, Chrome Ragamuffin returns the memory offset (Document offset) and the virtual address of the first DOM element (*html* tag). The *URL* and *Title* fields show us the URL of the *Document* and the *title* tag content rispectively. At last, every tab in Google Chrome is a separate thread and every object is associated to its tab PID.

2) Extract the DOM Tree in dot language of a document:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump.vmem chrome_ragamuffin -p 540 --documents 0x3b7f3d225a0 --dom 0x3b7f3d231d0 --output dot --output-file econom.dot
```
- http://192.168.1.135/econom.html:
![DOT DOM Tree](https://github.com/MalfurionStormrage/chrome_ragamuffin/blob/master/540.png)

3) Print the DOM Tree in text mode:
```sh
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump.vmem chrome_ragamuffin -p 540 --documents 0x3b7f3d225a0 --dom 0x3b7f3d231d0
Volatility Foundation Volatility Framework 2.6
Pid      Document offset      URL                                                Title                                              DOM start address
-------- -------------------- -------------------------------------------------- -------------------------------------------------- -----------------
INFO    : volatility.debug    : Running on process PID 540 PROC_NAME chrome.exe
     540 0x3b7f3d225a0        http://192.168.1.135/econom.html                   None                                               0x3b7f3d231d0L   
Node tag: html
Node attributes: {}
Memory offset: 0x3b7f3d231d0

Node tag: head
Node attributes: {}
Memory offset: 0x3b7f3d23238

Node tag: title
Node attributes: {}
Memory offset: 0x3b7f3d232a0

Node tag: Text
Content: 

Node tag: body
Node attributes: {}
Memory offset: 0x3b7f3d23360

Node tag: Text
Content: 

Node tag: center
Node attributes: {}
Memory offset: 0x3b7f3d23418

Node tag: Text
Content: 

Node tag: h1
Node attributes: {}
Memory offset: 0x3b7f3d234d0

Node tag: Text
Content: CONGRATS!

Node tag: hr
Node attributes: {}
Memory offset: 0x3b7f3d23588

Node tag: Text
Content: 

Node tag: img
Node attributes: {'src': './img.jpg'}
Memory offset: 0x3b7f3d23640

Node tag: hr
Node attributes: {}
Memory offset: 0x3b7f3d23710

Node tag: Text
Content: 

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

Node tag: Text
Content: 

Node tag: Text
Content: 

```

##Analysis with *volshell* plugin:
Below, I'll show you some example using Volatility volshell plugin. With its help we can perform a targeted analysis on DOM's elements that interest us.

1) Get DOM Tree:

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
2) Search for iframe nodes:
```sh
In [8]: iframe = [x for x in dom if x.tagName == "iframe"]
In [13]: dt(iframe[0])
[_html_iframe_element HTMLIframeElement] @ 0x3B7F3D237C8
0x0   : Element                        4088604538824
0x70  : m_contentFrame                 2124868027416
0x98  : m_URL
```
3) Get the page contained in the iframe:
```sh
In [14]: page_contained = iframe[0].contentDocument
In [15]: page_contained
Out[15]: [_document m_document] @ 0x3B7F3D261D0
In [16]: page_contained.title
Out[16]: '138.68.93.144'
In [17]: page_contained.url_string
Out[17]: 'data:text/html,chromewebdata'
```
We can assume that the page contained in the iframe element is the last blink::Document returned from the chrome_ragamuffin table output above:
```sh
540 0x3b7f3d261d0        data:text/html,chromewebdata                       138.68.93.144                                      0x3b7f3d26e60
```
