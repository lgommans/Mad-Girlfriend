#!/usr/bin/env python

from alertgenerator import Alert

import re

class Checkers:
    def postpassword(packet, alerter):
        if re.search('(pass|password|passwd|pwd)=[ -~]{3,}', packet.data) != None:
            extraFields = [["myExtraField", "string", "some extra value"], ["Current temperature", "count", 22]]
            alerter.log(Alert.CRITICAL, packet, extraFields)
