#!/usr/bin/env python
import argparse
import sys
import os
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


from switch_int_sr.int_off_sr_off import *
from switch_int_sr.int_on_sr_on import *
from switch_int_sr.int_on_sr_off import *
from switch_int_sr.int_off_sr_on import *

def send_int_message(ip_add, message, loops, sr_choice, ports):
# sr_choice: weather needs SR or not
    if sr_choice:
        int_on_sr_on_main(ip_add, message, loops, ports)
    else:
        int_on_sr_off_main(ip_add, message, loops)



def send_general_message(ip_add, message, loops, sr_choice, ports):
    if sr_choice:
        int_off_sr_on_main(ip_add, message, loops, ports)

    else:
        int_off_sr_off_main(ip_add, message, loops)

def send_message(ip_add, message, int_choice, loops, sr_choice, ports):
   # int_choice: wheather needs INT or not
   # sr_choice: wheather use SR or not
    if int_choice:
        send_int_message(ip_add, message, loops, sr_choice, ports)
    else:
        send_general_message(ip_add, message, loops, sr_choice, ports)
        


if __name__ == '__main__':



    ip_add = '10.0.2.2'
    message = 'hello'
    loops = 1000
    ports = '432'
    ports1 = '32'

    # in h2 run ./receive-mri.py
    
    send_message(ip_add, message, False, loops, True, ports)
    
    #send_message(ip_add, message, loops, True, ports)


    #pid = os.fork()

    #if pid == 0:
     #   send_message(ip_add, message, True, loops, True, ports)
      #  pass
    #else:
     #   send_message(ip_add, message, True, loops, True, ports1)


 