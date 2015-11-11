#!/usr/bin/env python

# This file is part of the Mad Girlfriend software
# COPYRIGHT 2015 Raoul Houkes & Luc Gommans
# All rights reserved.

from packetparser import Packet
from decimal import Decimal
import time

class Alert:
    CRITICAL = 'Critical'
    HIGH = 'High'
    MODERATE = 'Moderate'
    LOW = 'Low'
    INFO = 'Info'
    DEBUG = 'Debug'

class Alerter:
    # name:type
    _defaultFields = [[ 'ts', 'time']
        , [ 'uid', 'string' ]
        , [ 'saddr', 'addr' ]
        , [ 'sport', 'port' ]
        , [ 'daddr', 'addr' ]
        , [ 'dport', 'port' ]
        , [ 'prio', 'enum' ]
    ]

    def __init__(self, name):
        self.name = name
        self._wroteHeader = False
        self.state = {}
        self._fields = Alerter._defaultFields[:] # make a copy of the list

    def _writeHeader(self, extravalues):
        if extravalues != None:
            for row in extravalues:
                self._fields.append([row[0], row[1]])

        fields = ''
        types = ''
        for field in self._fields:
            fields += ' ' + field[0]
            types += ' ' + field[1]

        header = ['#separator \\x09\n'
            + '#set_separator ,\n'
            + '#empty_field (empty)\n'
            + '#unset_field -\n'
            + '#path ' + self.name + '\n'
            + '#open ' + time.strftime('%Y-%m-%d-%H-%M-%S') + '\n'
            + '#fields' + fields + '\n'
            + '#types' + types + '\n'][0] # This array construction is so I can do a multi-line string

        self._logfile = open(self.name + ".log", 'w')
        self._logfile.write(header)
        self._wroteHeader = True

    # Turn the {key: value, ...} dictionary into a [[key, value], [...]] list, preserving order of the original, and updating the values.
    def _setValues(self, kv):
        existingFields = self._fields[:] # make a copy of the list (original order)
        for key in kv:
            value = kv[key]
            index = 0
            found = False
            for field in existingFields:
                if field[0] == key:
                    found = True
                    break
                index += 1
            if index == -1: # Key not found in original list
                # Does this mean the extravalues list is variable?!
                existingFields.append([key, value])
            else:
                existingFields[index][1] = value
        return existingFields

    def log(self, level, packet = None, extravalues = None):
        # A packet may not be given (e.g. for canary events, where the actual packet is irrelevant)
        if packet == None:
            # In that case, forge a packet so we have a uid
            packet = Packet('')

        if not self._wroteHeader:
            self._writeHeader(extravalues)

        # Set default values for the log line
        values = {}
        values['ts'] = str(Decimal(packet.creationTime))[:17]
        values['uid'] = packet.uid()
        values['saddr'] = packet.saddr
        values['sport'] = packet.sport
        values['daddr'] = packet.daddr
        values['dport'] = packet.dport
        values['prio'] = level

        # Do we have extra values? Set the values
        if extravalues != None:
            for row in extravalues:
                values[row[0]] = row[2]

        values = self._setValues(values)

        # Build the line we'll write to the logfile
        logline = ''
        tab = ''
        for col in values:
            logline += tab + str(col[1])
            tab = "\x09"

        self._logfile.write(logline + '\n')
        # It's bad practice to flushing on all (well, most) writes, but it does need to get to
        # logstash in realtime. Perhaps build a time-based caching mechanism to cache briefly?
        self._logfile.flush()

        # Info- (e.g. canary) and debug-level events are not dumped
        if level != Alert.INFO and level != Alert.DEBUG:
            packet.dump()

    def close(self):
        # Close the log file gracefully
        if self._wroteHeader:
            self._logfile.write('#close ' + time.strftime('%Y-%m-%d-%H-%M-%S') + '\n')
            self._logfile.close()

