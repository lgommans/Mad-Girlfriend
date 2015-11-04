#!/usr/bin/env python

from rules import Checkers
from alertgenerator import Alerter
from packetparser import Packet

import signal, sys, os, socket

checkers = []
for methodName in Checkers.__dict__:
    if methodName[0] != '_':
        checkers.append((Checkers.__dict__[methodName], Alerter(methodName)))

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
    print('Error creating socket. Error Code: ' + str(msg[0]) + ', message: ' + msg[1])
    sys.exit(1)

try:
    while True:
        data = s.recvfrom(65565)[0]

        for checker, alerter in checkers:
            checker(Packet(data), alerter)
except KeyboardInterrupt:
    print("Received SIGINT")
    for checker, alerter in checkers:
        alerter.close()

