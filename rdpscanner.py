#!/usr/bin/env python

import sys
import os
import argparse
import io
import json
import time
import netaddr
import threading
from socket import *
from rdpy.protocol.rdp import rdp
from rdpy.protocol.rfb import rfb
from twisted.internet import reactor

class MyRFBFactory(rfb.ClientFactory):

    def clientConnectionLost(self, connector, reason):
        print "VNC Connection Lost: Reason: " + '%s%' % reason
        reactor.stop()
        pass

    def clientConnectionFailed(self, connector, reason):
        print "VNC Connections Failed: Reason: " + '%s' % reason
        reactor.stop()
        pass

    def buildObserver(self, controller, addr):
        class MyObserver(rfb.RFBClientObserver):

            def onReady(self):
                """
                @summary: Event when network stack is ready to receive or send event
                """

            def onUpdate(self, width, height, x, y, pixelFormat, encoding, data):
                """
                @summary: Implement RFBClientObserver interface
                @param width: width of new image
                @param height: height of new image
                @param x: x position of new image
                @param y: y position of new image
                @param pixelFormat: pixefFormat structure in rfb.message.PixelFormat
                @param encoding: encoding type rfb.message.Encoding
                @param data: image data in accordance with pixel format and encoding
                """

            def onCutText(self, text):
                """
                @summary: event when server send cut text event
                @param text: text received
                """

            def onBell(self):
                """
                @summary: event when server send biiip
                """

            def onClose(self):
                """
                @summary: Call when stack is close
                """

        return MyObserver(controller)

class MyRDPFactory(rdp.ClientFactory):

    def clientConnectionLost(self, connector, reason):
        print "RDP Connection Lost: Reason: " + '%s' % reason
        reactor.stop()
        pass

    def clientConnectionFailed(self, connector, reason):
        print "RDP Connection Failes: Reason: " + '%s' % reason
        reactor.stop()
        pass

    def buildObserver(self, controller, addr):

        class MyObserver(rdp.RDPClientObserver):

            def onReady(self):
                """
                @summary: Call when stack is ready
                """
                #send 'r' key
                self._controller.sendKeyEventUnicode(ord(unicode("r".toUtf8(), encoding="UTF-8")), True)
                #mouse move and click at pixel 200x200
                self._controller.sendPointerEvent(200, 200, 1, true)

            def onUpdate(self, destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data):
                """
                @summary: Notify bitmap update
                @param destLeft: xmin position
                @param destTop: ymin position
                @param destRight: xmax position because RDP can send bitmap with padding
                @param destBottom: ymax position because RDP can send bitmap with padding
                @param width: width of bitmap
                @param height: height of bitmap
                @param bitsPerPixel: number of bit per pixel
                @param isCompress: use RLE compression
                @param data: bitmap data
                """

            def onSessionReady(self):
                        """
                        @summary: Windows session is ready
                        """

            def onClose(self):
                """
                @summary: Call when stack is close
                """

        return MyObserver(controller)

def rdpscan(server, port, proto, results_file):
#    print "Attempting RDP scan on " + '%s' % server + '\n'
    ts = time.time()
    try:
        if proto == 'RDP':
            print "Attempting RDP scan on " + '%s' % server + '\n'
            rdpshot = reactor.connectTCP(server, port, MyRDPFactory())
            rdpshot = reactor.run()
        else:
            print "Attempting VNC scan on " + '%s' % server + '\n'
            rdpshot = reactor.connectTCP(server, port, MyRFBFactory())
            rdpshot = reactor.run()
        if results_file is not None:
            with print_lock:
                with open(rdpargs.results_file, 'a+') as screenshot:
                    screenshot.write('%s' % rdpshot)
        else:
            print server + ': ' + '%s' % rdpshot + '\n'
            pass
    except:
        try:
            connector = socket(AF_INET, SOCK_STREAM)
            connector.settimeout(1)
            connector.connect(('%s' % server, port))
            connector.send('Friendly Portscanner\r\n')
            rdp_entry = connector.recv(2048)
            connector.close()
            if results_file is not None:
                with print_lock:
                    with open(results_file, 'a+') as outfile:
                       rdp_data = 'host: ' + '%s' % server + '\n' + 'is_rdp: false\nrdp_info:' + '%s' % rdp_entry + '\nrdp_port: ' + '%s' % port + '\ntimestamp: ' + '%s' % ts + '\n\n'
                       outfile.write(rdp_data)
            else:
                with print_lock:
                    print ("[-] " + '%s' % server + ": " + '%s' % rdp_entry + '\n')
                    pass
        except Exception, errorcode:
            if errorcode[0] == "timed out":
                print server + ": connection " + errorcode[0] + "\n"
                pass
            elif errorcode[0] == "connection refused":
                print server + ": connection " + errorcode[0] + "\n"
                pass
            else:
                pass
        
def thread_check(server, results_file):
    global semaphore

    try:
        rdpscan(server, rdp.args.port, rdpargs.proto, results_file)
    except Exception as e:
        with print_lock:
           print "I ended up here \n"
           print "[ERROR] [%s] - %s" % (server, e)
    finally:
        semaphore.release()


if __name__ == "__main__":
    rdpparser = argparse.ArgumentParser(description="RDP and VNC Scanner")
    rdpparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")
    rdpparser.add_argument("-ip", type=str, required=False, help="IP address to scan")
    rdpparser.add_argument("-proto", type=str, required=True, help="RDP or VNC")
    rdpparser.add_argument("-port", type=int, required=True, help="Ports for RDP or VNC")
    rdpparser.add_argument("-results_file", type=str, required=True, help="Results File")
    rdpparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")
    rdpargs = rdpparser.parse_args()

    semaphore = threading.BoundedSemaphore(value=rdpargs.packet_rate)
    print_lock = threading.Lock()

    if rdpargs.ip is not None:
        rdpscan(rdpargs.ip, rdpargs.port, rdpargs.proto, rdpargs.results_file)

    elif rdpargs.netrange is not None:
       for ip in netaddr.IPNetwork(rdpargs.netrange).iter_hosts():
           rdpscan(str(ip), rdpargs.port, rdpargs.proto, rdpargs.results_file)

    elif not rdpargs.packet_rate and rdpargs.netrange:
       for ip in netaddr.IPNetwork(rdpargs.netrange).iter_hosts():
           semaphore.acquire()
           rdpthread = threading.Thread(target=thread_check, args=(str(ip), rdpargs.results_file))
           rdpthread.start()
           rdpthread.join()
    else:
        print "Please provide with either -ip or -netrange.  Or ./rdpscanner.py -h for help.."
        exit
