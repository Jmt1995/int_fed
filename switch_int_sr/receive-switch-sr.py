#!/usr/bin/env python
import sys
import struct
import os


from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import IP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *

from choose_host.db import *


def recev_log(pkt):
    
    strinfo =  time.strftime('[%Y-%m-%d-%H:%M:%S]\t',time.localtime(time.time()))
    hostname = socket.gethostname()

    dst = pkt.getlayer(IP).dst
    src = pkt.getlayer(IP).src 



    raw = pkt.getlayer(Raw).load 

       
    if  pkt.getlayer(IPOption_MRI) is None:
      loginfo = strinfo +  dst + ' receive a packet from ' + src + '\tmessage: ' + raw + '\n'

    else:
      sw_count1 = pkt.getlayer(IPOption_MRI).count
      loginfo = strinfo +  dst + ' receive a INT packet from ' + src
      

      switchinfo = ''

      before = -1
      for i in range (0, sw_count1):
        swid = pkt.getlayer(IPOption_MRI).swtraces[i].swid
        qdepth = pkt.getlayer(IPOption_MRI).swtraces[i].qdepth

        switchinfo += ' switch' + str(swid) + ': ' + str(qdepth)

        conn = DBConn()
   
        device_next_no = before
        before = swid
        deq_timedelta = time.time()
        conn.write('insert into `info_int` (`device_no`,`device_next_no` ,`enq_qdepth`,`deq_timedelta`) values ('+str(swid)+','+str(device_next_no)+','+str(qdepth)+ ','+str(deq_timedelta)+');')

        if i != sw_count1-1:
          switchinfo += ' <- '
        
      loginfo += switchinfo + '\tmessage: '+ raw + '\n'

    f = open('mriwrite.txt', 'a')
    f.write(loginfo)
    f.close()
    print loginfo

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

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

def handle_pkt(pkt):
    #print "got a packet"
    #pkt.show2()
    recev_log(pkt)
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    iface = 'h2-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
    