# Chrome Ragamuffin
Volatility plugins to extract some useful information from Google Chrome's address space.

The goal of this plugin is to make possible the analysis of a Google Chrome running instance. Starting from a memory dump, 
Chrome Ragamuffin can list which page was open on which tab and it is able to extract the DOM Tree in order to analyze the full page structure.

At this time, Chrome Ragamuffin can scan for *blink::Document* objects in memory and extract their DOM tree in dot language. To perform an in-depth analysis of the nodes content, you can go through volshell plugin and work with its API.

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
$ ./volatility --plugins $PATH_TO_RAGAMUFFIN_DIR --profile Win10x64_14393 -f dump.vmem chrome_ragamuffin -p 540 --documents 0x3b7f3d225a0 --output dot --output-file econom.dot
```
- http://192.168.1.135/econom.html:
![DOT DOM Tree](https://github.com/MalfurionStormrage/chrome_ragamuffin/blob/master/540.png)
