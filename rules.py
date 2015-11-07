#!/usr/bin/env python

from alertgenerator import Alert

import re

class Checkers:
    def canary(packet, alerter):
        if 'lastalert' not in alerter.state:
            alerter.state['lastalert'] = 0

        if time.time() - alerter.state['lastalert'] > 30:
            alerter.state['lastalert'] = time.time()
            extravalues = [['packetsHandled', 'count', alerter.state['packetsHandled']]]
            alerter.log(Alert.INFO, None, extravalues)

    def postpassword(packet, alerter):
        if re.search('(pass|password|passwd|pwd)=[ -~]{3,}', packet.data) != None:
            extraFields = [["myExtraField", "string", "some extra value"], ["Current_temperature", "count", 22]]
            alerter.log(Alert.CRITICAL, packet, extraFields)

