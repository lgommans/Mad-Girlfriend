#!/usr/bin/env python

from rules import Rules
from alertgenerator import Alert, Alerter
from packetparser import Packet

import signal, sys, os, socket, time, traceback, exceptions

def getMemoryUsage():
    data = open('/proc/meminfo', 'r').read(2048).split('\n')
    memFree = int(data[1].split(':')[1].strip().split(' ')[0]) # kb
    buffers = int(data[3].split(':')[1].strip().split(' ')[0]) # kb
    cached = int(data[4].split(':')[1].strip().split(' ')[0]) # kb
    # Available memory is what is free (completely unoccupied) plus what can
    # can be emptied on demand (i.e. buffers and cache). The number returned
    # by this function is how many KBs more python can use before OOM.
    totalUsableMemory = memFree + buffers + cached
    return totalUsableMemory

def canary(packet, alerter):
    global lastPacketsHandled, lastBytesHandled
    # The canary chirps its status every now and then
    nowandthen = 15 # seconds

    if 'lastalert' not in alerter.state:
        alerter.state['lastalert'] = 0

    elapsedSinceLastCanary = time.time() - alerter.state['lastalert']
    if elapsedSinceLastCanary > nowandthen:
        alerter.state['lastalert'] = time.time()
        ph = ['packetsHandled', 'count', lastPacketsHandled / elapsedSinceLastCanary]
        tph = ['totalPacketsHandled', 'count', packetsHandled]
        bh = ['bytesHandled', 'count', lastBytesHandled / elapsedSinceLastCanary]
        tbh = ['totalBytesHandled', 'count', bytesHandled]
        memusage = ['memusage', 'count', getMemoryUsage()]
        loadavg = ['loadavg', 'count', os.getloadavg()[0]]
        extravalues = [tph, tbh, memusage, loadavg, ph, bh]
        alerter.log(Alert.INFO, None, extravalues)

        lastPacketsHandled = 0 # since last canary
        lastBytesHandled = 0 # since last canary

# The rules array contains all rules we apply to each packet.
# The canary function, defined above, is always present.
rules = [(canary, Alerter('canary'))]
for methodName in Rules.__dict__:
    if methodName[0] != '_':
        if methodName == 'canary':
            print("Error: you cannot have a rule named 'canary'. This is a reserved name.")
            sys.exit(4)
        rules.append((Rules.__dict__[methodName], Alerter(methodName)))
    else:
        if methodName not in ['__module__', '__doc__']:
            print("Ignoring method '" + methodName + "' because it starts with an underscore.")

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
    print('Error creating socket. Error Code: ' + str(msg[0]) + ', message: ' + msg[1])
    sys.exit(1)

print("Mad Girlfriend initialized.")

packetsHandled = 0
bytesHandled = 0
lastPacketsHandled = 0 # since last canary
lastBytesHandled = 0 # since last canary
try:
    while True:
        data = s.recvfrom(65565)[0]

        for rule, alerter in rules:
            try:
                rule(Packet(data), alerter)
            except:
                if sys.exc_info()[0] is exceptions.KeyboardInterrupt:
                    raise
                else:
                    sys.stderr.write("Error in rule {}: {}: {}\n{}".format(alerter.name, \
                        sys.exc_info()[0], sys.exc_info()[1], traceback.print_tb(sys.exc_info()[2])))

        packetsHandled += 1
        lastPacketsHandled += 1
        lastBytesHandled += len(data)
        bytesHandled += len(data)

except KeyboardInterrupt:
    print("Received SIGINT")
    for rule, alerter in rules:
        print("Closing " + alerter.name + ".log")
        alerter.close()
    print("Done! Have a nice day :)")

