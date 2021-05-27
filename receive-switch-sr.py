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

#from choose_host.db import *


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

  
   
        device_next_no = before
        before = swid
        deq_timedelta = time.time()
  
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
    fields_desc = [ 
        BitField("swid", 0, 14),
        BitField("ingress_port", 0, 9),
        BitField("egress_port", 0, 9),
        IntField("deq_timedelta", 0),
        BitField("ingress_global_timestamp", 0, 48),
        BitField("egress_global_timestamp", 0, 48)]
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
    pkt.show2()
    #recev_log(pkt)
#    hexdump(pkt)
    p1 = pkt.copy()
    print "got a packet"
    p1_bytes = bytes(p1)


    rec_pkg = dict()


    
    if pkt.getlayer(IPOption_MRI) is not None:
      
      int_count  = pkt.getlayer(IPOption_MRI).count
      #print 'ok', int_count
      int_begin = 0
      etr_ip_length  = 38
      each_int_lenth = 20
      udp_length = 8

      int_lists = list()
      
      for index in range(int_count):
        each_int_item = dict()

        item = SwitchTrace(p1_bytes[etr_ip_length+int_begin+0:etr_ip_length+int_begin+each_int_lenth])
        item.show()
        each_int_item['swid'] =  item.swid
        each_int_item['ingress_port'] =    item.ingress_port
        each_int_item['egress_port'] =   item.egress_port
        each_int_item['ingress_global_timestamp'] =   item.ingress_global_timestamp
        each_int_item['egress_global_timestamp'] =   item.egress_global_timestamp

        int_begin += each_int_lenth

        int_lists.append(each_int_item)

      UDP(p1_bytes[etr_ip_length+int_begin: etr_ip_length+int_begin+udp_length]).show()
      data = p1_bytes[etr_ip_length+int_begin+udp_length:]
      print 'int packet'
      print int_lists
      int_lists =  list(reversed(int_lists))
     # time.sleep(100)
      rec_pkg['int_lists'] = int_lists
      rec_pkg['data'] = data
      print data

    else:
      print 'general packet'
      data = pkt.getlayer(Raw).load
      print data


    for item in rec_pkg['int_lists']:
      print item
    #print rec_pkg_li
    sys.stdout.flush()


def main():
    iface = 'h2-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and ip host 10.0.1.1", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
    