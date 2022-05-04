#!/usr/bin/env python3

import socket
import sys
from time import sleep

from scapy.all import (
    IP,
    UDP,
    Ether,
    Packet,
    bind_layers,
    get_if_hwaddr,
    get_if_list,
    sendp,

    FieldLenField,
    IntField,
    IPOption,
    PacketListField,
    ShortField

)
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
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

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    while True:
        print()
        s = str(input('Type space separated port nums '
                          '(example: "4 2 3 4 2") or "q" to quit: '))
        if s == "q":
            break;
        print()

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

        pkt = pkt / IP(dst=addr, options = IPOption_MRI(count=0,
                   swtraces=[])) / UDP(dport=4321, sport=1234) / sys.argv[2]
        pkt.show2()
        # sendp(pkt, iface=iface, verbose=False)
        try:
          for i in range(int(sys.argv[3])):
            sendp(pkt, iface=iface)
            sleep(1)
        except KeyboardInterrupt:
            raise


 #    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
 #        dst=addr, options = IPOption_MRI(count=0,
 #            swtraces=[])) / UDP(
 #            dport=4321, sport=1234) / sys.argv[2]
 #
 # #   pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
 # #       dst=addr, options = IPOption_MRI(count=2,
 # #           swtraces=[SwitchTrace(swid=0,qdepth=0), SwitchTrace(swid=1,qdepth=0)])) / UDP(
 # #           dport=4321, sport=1234) / sys.argv[2]
 #    pkt.show2()
 #    #hexdump(pkt)
 #    try:
 #      for i in range(int(sys.argv[3])):
 #        sendp(pkt, iface=iface)
 #        sleep(1)
 #    except KeyboardInterrupt:
 #        raise


if __name__ == '__main__':
    main()
