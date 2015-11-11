#!/usr/bin/env python

# This file is part of the Mad Girlfriend software
# COPYRIGHT 2015 Raoul Houkes & Luc Gommans
# All rights reserved.

# Credits: Silver Moon (m00n.silv3r@gmail.com) for parsing the Ethernet, IP, TCP, UDP and ICMP packet headers.

import socket, sys, os, base64, time
from struct import *

class Packet:
    eth_length = 14

    def uid(self):
        if self._uidset == False:
            while True:
                uid = base64.b64encode(os.urandom(9))
                if '/' not in uid and '+' not in uid:
                    break
            self._uid = uid
            self._uidset = True
        return self._uid

    def __init__(self, rawPacket):
        # To be sure it's the right time, let this be the first thing we do
        self.creationTime = time.time()

        # Set some defaults so it doesn't break when we ask something without checking stuff first...
        self.saddr = '-'
        self.daddr = '-'
        self.sport = '-'
        self.dport = '-'
        self.ipversion = '-'
        self.type = 'unknown'
        self.subtype = 'unknown'
        self._uidset = False

        # In case the protocol is unknown, data is set to rawPacket
        self.rawPacket = rawPacket
        self.data = rawPacket

        if len(rawPacket) < Packet.eth_length:
            return

        eth_header = rawPacket[:Packet.eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])

        self.ethprotocol = eth_protocol
        self.smac = self._eth_addr(rawPacket[6:12])
        self.dmac = self._eth_addr(rawPacket[0:6])

        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8:
            ip_header = rawPacket[Packet.eth_length:20+Packet.eth_length]

            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            self.ipversion = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]

            self.ipprotocol = protocol
            self.saddr = socket.inet_ntoa(iph[8]);
            self.daddr = socket.inet_ntoa(iph[9]);

            #TCP protocol
            if protocol == 6:
                self.type = 'tcp'

                t = iph_length + Packet.eth_length
                tcp_header = rawPacket[t:t+20]

                tcph = unpack('!HHLLBBHHH' , tcp_header)

                self.sport = tcph[0]
                self.dport = tcph[1]
                self.seqnum = tcph[2]
                self.acknum = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                h_size = Packet.eth_length + iph_length + tcph_length * 4
                data_size = len(rawPacket) - h_size

                self.data = rawPacket[h_size:]

            #ICMP Packets
            elif protocol == 1:
                self.type = 'icmp'

                u = iph_length + Packet.eth_length
                icmph_length = 4
                icmp_header = rawPacket[u:u+4]

                #now unpack them :)
                icmph = unpack('!BBH' , icmp_header)

                self.icmp_type = icmph[0]
                self.code = icmph[1]
                checksum = icmph[2]

                h_size = Packet.eth_length + iph_length + icmph_length
                data_size = len(rawPacket) - h_size

                self.data = rawPacket[h_size:]

            #UDP packets
            elif protocol == 17 :
                self.type = 'udp'
                u = iph_length + Packet.eth_length
                udph_length = 8
                udp_header = rawPacket[u:u+8]

                udph = unpack('!HHHH' , udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                h_size = Packet.eth_length + iph_length + udph_length
                data_size = len(rawPacket) - h_size

                self.data = rawPacket[h_size:]
                self.sport = source_port
                self.dport = dest_port
            else:
                #some other IP packet like IGMP
                self.type = 'unknown'
                self.subtype = 'ip'
        else:
            # All we know is that it's probably ethernet
            self.type = 'unknown'
            self.subtype = 'probably-ethernet'

    def _eth_addr(self, a):
      return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))

    def dump(self):
        folder = 'dumps/' + time.strftime('%Y-%m-%d_%H-%M')

        if not os.path.isdir(folder):
            os.makedirs(folder)

        if not os.path.isfile(folder + '/' + self.uid()):
            f = open(folder + '/' + self.uid(), 'w')
            f.write(self.rawPacket)
            f.close()

