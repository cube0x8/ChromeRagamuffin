# Chrome Ragamuffin
Volatility plugins to extract some useful information from Google Chrome's address space.

The goal of this plugin is to make possible the analysis of a Google Chrome running instance. Starting from a (only Windows, currently) memory dump, 
Chrome Ragamuffin can list which page was open on which tab and it is able to extract the DOM Tree in order to analyze the full page structure.

### Some examples:
1) extract all available blink::Document objects in memory with their respective memory offset
```sh
$ ./volatility_2.6_win64_standalone.exe --plugins ragamuffin/ --profile Win10x64_14393 -f /g/dump.vmem chrome_ragamuffin

Pid      Document offset      URL                                                Title                                             
-------- -------------------- -------------------------------------------------- --------------------------------------------------
    4384 0x3f8c0aa25a0        https://truel.it/                                  TRUEL IT | Home                                   
    3184 0x34da48225a0        https://www.google.it/                             Google                                            
    3948 0x35c2ff825a0        https://twitter.com/                               Twitter. � ci� che sta accadendo.                 
    3948 0x35c2ffc1838        https://twitter.com/i/vi...&player_id=1&rpc_init=1 Twitter web player                                
    3948 0x35c2ffc2468        https://twitter.com/i/vi...&player_id=0&rpc_init=1 Twitter web player                                
    3948 0x35c2ffe1838        about:blank                                        None                                              
    3948 0x35c2ffe4260        about:blank                                        None                                              
    3948 0x35c2ffea3e0        about:blank                                        None                                              
    3948 0x35c2ffec050        about:blank                                        None                                              
    3948 0x35c30003ec0        about:blank                                        None                                              
    3948 0x35c30009048        about:blank                                        None                                              
    3948 0x35c30013ce8        about:blank                                        None                                              
    3948 0x35c3001d810        https://twitter.com/push_service_worker.js         None                                              
    3588 0x4d67092f220        https://app.tutanota.com/#box                      vulwdfhvl@tuta.io - Tutanota                      
     540 0x3b7f3d225a0        http://192.168.1.135/econom.html                   None                                              
     540 0x3b7f3d261d0        data:text/html,chromewebdata                       138.68.93.144     
```
2) now, you can analyze a single blink::Document and extract its DOM Tree
```sh
$ ./volatility_2.6_win64_standalone.exe --plugins ragamuffin/ --profile Win10x64_14393 -f /g/dump.vmem chrome_ragamuffin -p 540 --documents 0x3b7f3d225a0 --dom_analysis full --output dot --output-file domtree.dot
```
![DOT DOM Tree](https://raw.githubusercontent.com/MalfurionStormrage/chrome_ragamuffin/master/domtree.png)
