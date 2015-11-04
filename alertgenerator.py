#!/usr/bin/env python

import time

class Alert:
    CRITICAL = 'Critical'
    HIGH = 'High'
    MODERATE = 'Moderate'
    LOW = 'Low'

class Alerter:
    # name:type
    fields = [[ 'ts', 'time']
        , [ 'uid', 'string' ]
        , [ 'saddr', 'addr' ]
        , [ 'sport', 'port' ]
        , [ 'daddr', 'addr' ]
        , [ 'dport', 'port' ]
        , [ 'prio', 'enum' ]
    ]

    # filename is without .log!
    def __init__(self, filename):
        self.filename = filename
        self.logfile = open(filename + ".log", 'w')
        self.wroteHeader = False
        self.fields = Alerter.fields[:] # make a copy of the list

    def writeHeader(self, extravalues):
        for row in extravalues:
            self.fields.append([row[0], row[1]])

        fields = ''
        types = ''
        for field in self.fields:
            fields += ' ' + field[0]
            types += ' ' + field[1]

        header = ['#separator \x09\n'
            + '#set_separator ,\n'
            + '#empty_field (empty)\n'
            + '#unset_field -\n'
            + '#path ' + self.filename + '\n'
            + '#open ' + time.strftime('%Y-%m-%d-%H-%M-%S') + '\n'
            + '#fields' + fields + '\n'
            + '#types' + types + '\n'][0]

        self.logfile.write(header)
        self.wroteHeader = True

    def setValues(self, kv):
        row = self.fields[:] # make a copy of the list
        for key in kv:
            i = 0
            index = -1
            for field in row:
                if field[0] == key:
                    index = i
                    break
                i += 1
            if index == -1:
                row.apppend([key, kv[key]])
            else:
                row[i][1] = kv[key]
        return row

    def log(self, level, packet, extravalues = None):
        if not self.wroteHeader:
            self.writeHeader(extravalues)

        values = {}
        values['ts'] = time.time()
        values['uid'] = packet.uid
        values['saddr'] = packet.saddr
        values['sport'] = packet.sport
        values['daddr'] = packet.daddr
        values['dport'] = packet.dport
        values['prio'] = level

        for row in extravalues:
            values[row[0]] = row[2]

        values = self.setValues(values)

        logline = ''
        for col in values:
            logline += str(col[1]) + "\x09"

        self.logfile.write(logline + '\n')
        self.logfile.flush() # Bad practice, flushing on all (well, most) writes, but it does need to get to logstash in realtime. Perhaps build a time-based caching mechanism to cache briefly?

        packet.dump()

    def close(self):
        if self.wroteHeader:
            self.logfile.write('#close ' + time.strftime('%Y-%m-%d-%H-%M-%S') + '\n')
            self.logfile.close()

