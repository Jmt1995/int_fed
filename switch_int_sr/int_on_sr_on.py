#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.fields import *



from scapy.all import hexdump
from scapy.all import IPOption
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR

from time import sleep

import readline



def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)


def emphasize(s):
    s = s.replace('',' ')
    return s

def send_log():
    f = open('messread.txt', 'a')
    strinfo =  time.strftime('[%Y-%m-%d-%H:%M:%S]\t',time.localtime(time.time()))
    hostname = socket.gethostname()
    strinfo = strinfo + hostname + '\tsend a packet\n'
    print strinfo
    f.write(strinfo)
    f.close()

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]



def int_on_sr_on_main(ip_add, message, loops, ports):


    if ip_add is None:
        print 'lack arguments: ip'
        exit(1)

    if message is None:
        print 'lack arguments: message'
        exit(1)

    if loops is None:
        print 'lack arguments: loops'
        exit(1)

    if ports is None:
        print 'lack arguments: ports'
        exit(1)
    #addr = socket.gethostbyname('10.0.2.2')

    addr = socket.gethostbyname(ip_add)
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))

    s = emphasize(ports)
    #s = emphasize(sys.argv[1])
    print('s:',s)


    i = 0
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
    for p in s.split(" "):
        try:
            pkt = pkt / SourceRoute(bos=0, port=int(p))
            i = i+1
        except ValueError:
            pass
    if pkt.haslayer(SourceRoute):
        pkt.getlayer(SourceRoute, i).bos = 1


    # if you dont want to trasfer data please hint "/ sys.argv[3]"

    pkt = pkt / IP(
        dst=addr, options = IPOption_MRI(count=0,
            swtraces=[])) / UDP(dport=4321, sport=1234) / message
    #pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234) / sys.argv[2]


    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

    send_log()

    try:
        for i in range(int(loops)):
            sendp(pkt, iface=iface)
            sleep(1)
    except KeyboardInterrupt:
        raise

    """
    while True:
        print
        s = str(raw_input('Type space separated port nums '
                          '(example: "2 3 2 2 1") or "q" to quit: '))
        if s == "q":
            break;
        print(s)

        i = 0
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
        for p in s.split(" "):
            try:
                pkt = pkt / SourceRoute(bos=0, port=int(p))
                i = i+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, i).bos = 1

        pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    """

    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=3);
    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=2);
    #pkt = pkt / SourceRoute(bos=1, port=1)


