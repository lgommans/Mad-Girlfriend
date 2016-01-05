#!/usr/bin/env python

# This file is part of the Mad Girlfriend software
# See the LICENSE file for copyright information

from alertgenerator import Alert

import re

class Rules:
    def postpassword(packet, alerter):
        if re.search('(pass|password|passwd|pwd)=[ -~]{3,}', packet.data) != None:
            extraFields = [["myExtraField", "string", "some extra value"], ["Current_temperature", "count", 22]]
            alerter.log(Alert.CRITICAL, packet, extraFields)

