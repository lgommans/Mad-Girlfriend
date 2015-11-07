#!/usr/bin/env python

from rules import Checkers
from alertgenerator import Alerter
from packetparser import Packet

import signal, sys, os, socket, traceback

checkers = []
for methodName in Checkers.__dict__:
    if methodName[0] != '_':
        checkers.append((Checkers.__dict__[methodName], Alerter(methodName), methodName))

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
    print('Error creating socket. Error Code: ' + str(msg[0]) + ', message: ' + msg[1])
    sys.exit(1)

try:
    packetsHandled = 0
    while True:
        data = s.recvfrom(65565)[0]

        for checker, alerter, checkerName in checkers:
            if checkerName == 'canary':
                alerter.state['packetsHandled'] = packetsHandled

            try:
                checker(Packet(data), alerter)
            except:
                sys.stderr.write("Error in checker {}: {}: {}\n{}".format(checkerName, \
                    sys.exc_info()[0], sys.exc_info()[1], traceback.print_tb(sys.exc_info()[2])))

        packetsHandled += 1

except KeyboardInterrupt:
    print("Received SIGINT")
    for checker, alerter in checkers:
        alerter.close()

