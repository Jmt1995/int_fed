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
import readline
from time import sleep

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
    f.write(strinfo)
    f.close()

def int_off_sr_on_main(ip_add, message, loops, ports):

 

    addr = socket.gethostbyname(ip_add)
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))

    s = emphasize(ports)
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

    pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234) / message
    pkt.show2()


    try:
      for i in range(int(loops)):
        sendp(pkt, iface=iface, verbose=False)
        send_log()
        sleep(1)
    except KeyboardInterrupt:
        raise
    

    


if __name__ == '__main__':
    main()
