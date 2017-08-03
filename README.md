# rdp-scan - This tool is also in beta and will be added to pycombo-scan.

Note: I have a lot of people asking for protocol specific scanners ASAP, so a lot of these are going into beta release initially
      with the intention to make them production ready when requests stop coming in.  lol
      
A scanner for verifying RDP and VNC services.

Lesson Learned
===

Example:

```bash
root@docker# ./ldapscanner.py -ip 192.168.10.5 -proto RDP -port 3389 -results_file results.txt
attempting to scan 192.168.10.5
root@docker#
```

If you use the "-results_file" flag, you should get a nice parseable output:  (This does not work yet.)

The file should look like the following:

Dependencies:
=============

rdpy
twisted

Usage:
======

```bash
./rdpscanner.py -h
```

RDP and VNC Checker

Example
===

```bash
./rdpscanner.py -ip 192.168.10.5 -port 1104 -proto RDP -results_file results.txt

./rdpscanner.py -netrange 192.168.10.0/24 -port 1104 -proto VNC -results_file results.txt
```

Bugs
====

- VNC errors can cause scanner to hang.  Need to fix this.
- Scanner can freeze if a non-VNC or RDP is running behind the port.  Needs a timeout handler in twisted.

TODO
===

- suppress, parse, and handle RDP and VNC error messages
- add printing to screen
- add screen grabbing
- fix bugs
                                                                                                                                                                                                                            1,1           Top
If you find other bugs that I haven't mentioned, please report them to gmail (rlastinger) or create a ticket, and I will get to it when I can.

Help or improvement suggestions are also welcome.  Just email me at gmail (rlastinger).
Enjoy.
