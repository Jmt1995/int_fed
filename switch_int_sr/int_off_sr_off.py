#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
from time import sleep
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

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

def int_off_sr_off_main(ip_add, message, loops):


    if ip_add is None:
        print 'lack arguments: ip'
        exit(1)

    if message is None:
        print 'lack arguments: message'
        exit(1)

    if loops is None:
        print 'lack arguments: loops'
        exit(1)
    addr = socket.gethostbyname(ip_add)
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) / UDP(dport=4321, sport=1234)  / message
    pkt.show2()

    try:
      for i in range(int(loops)):
        sendp(pkt, iface=iface, verbose=False)
        sleep(1)
    except KeyboardInterrupt:
        raise

        
