# Mad Girlfriend

An IDS with its rules written in Python.

## Usage

1. Add your desired rules to `rules.py` (see the file for an example, it's really simple!)

2. Use `cd /your/directory` to go to the directory where you want logs to be stored.

3. Run `/path/to/madgirlfriend.py` in that directory.

4. ???

5. Log files and packet dumps for the rules you have configured! You get a free canary event that logs uptime and system information :)

## Writing rules

Tired of Snort's complicated rules? Or even Bro with a custom scripting format?! These rules are plain Python.

Add a function in `rules.py` that accepts the arguments `packet` and `alerter`.
The `alerter` has two functions:

- it can store a state for you using `alerter.state["myfield"] = myvalue` and
- you use it to log events: `alerter.log(Alert.CRITICAL, packet)`

Alert types are: `CRITICAL`, `HIGH`, `MODERATE` and `LOW`. You can define your own in `alertgenerator.py`.

If you want additional data (not just timestamp, source and destination), define extra values using this format:

    extravalues = [['temperature', 'count', 44], ['name', 'type', value], ...]
    alerter.log(priority, packet, extravalues)

The `packet` argument that your function gets, contains with the following fields:

- `packet.type` = "icmp", "tcp", "udp" OR "unknown"
- `packet.subtype` = "ip" OR "unknown"
- `packet.daddr` = destination IP address
- `packet.saddr` = source IP address
- `packet.ipversion` = IP version (typically 4 or 6)
- `packet.dport` = destination port
- `packet.sport` = source port
- `packet.seqnum` = TCP sequence number
- `packet.acknum` = TCP acknowledgement number
- `packet.icmp_type` = ICMP packet type
- `packet.code` = ICMP code
- `packet.data` = payload
- `packet.rawPacket` = raw packet data (header + payload)

Of course non-applicable fields will be unset, e.g. `packet.dport` is unavailable when it's not a TCP or UDP packet.
Protocol detection is currently limited to IP, TCP, UDP and ICMP.
