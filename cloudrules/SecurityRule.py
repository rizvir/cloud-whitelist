"""
Simple class representing a security rule

A security rule is a named tuple that looks like:

( ip, netmask, from_port, to_port, protocol, description )

"""


from collections import namedtuple

SecurityRule = namedtuple('SecurityRule', "ip cidr from_port to_port \
                                protocol description")

