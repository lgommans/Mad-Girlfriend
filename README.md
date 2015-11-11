# Mad Girlfriend

An IDS where you can write your rules in Python.

## Usage

1. Add your desired rules to `rules.py` (see the file for an example, it's really simple!)

2. Use `cd /your/directory` to go to the directory where you want logs to be stored.

3. Run `/path/to/madgirlfriend.py` in that directory.

Done! You are now running an IDS.

## Design

The design goal of this project was to write an alternative to Snort, Suricata and Bro that is easy to configure and quick to setup. It is highly configurable and every aspect of the engine can be changed as it's quite easy to understand.

Of course an IDS needs to be resilient against exceptional conditions - that's what it's made to detect - and I believe we've achieved this due to extensive exception handling. If something goes wrong in a rule, which happens regularly when you're testing things out so I've seen it plenty of times, the engine will catch it and continue with the other rules as if nothing happened. The error will be printed to `stderr` together with a complete stack trace for easy debugging.

## Writing rules

Don't like Snort's complicated rules? Or Bro with its custom scripting language?! These rules are simple Python.

Add a function in `rules.py` that accepts the arguments `packet` and `alerter`.
The `alerter` has two functions:

- it can store a state for you using `alerter.state["myfield"] = myvalue` and
- you use it to log events: `alerter.log(Alert.CRITICAL, packet)`

Alert types are: `CRITICAL`, `HIGH`, `MODERATE` and `LOW`. You can define your own in `alertgenerator.py`.

If you want additional data (not just timestamp, source and destination), define extra values using this format:

    extravalues = [['temperature', 'count', 44], ['name', 'type', value], ...]
    alerter.log(priority, packet, extravalues)

The `packet` argument that your function accepts, contains the following fields:

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
