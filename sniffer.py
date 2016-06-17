#! /usr/bin/env python

# With modifacations from
# http://stackoverflow.com/questions/29306747/python-sniffing-from-black-hat-python-book
# The original solutions what 32-bit system dependent

import socket
import os
import struct
from ctypes import *
import threading
import time
from netaddr import IPNetwork, IPAddress

# host to listen on
host = "172.31.99.65"

# subnet to target
subnet = "172.31.99.0/23"

# magic string
magic_message = "ImJustLearning"

# IP header
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # human readable ip addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            # not in map, give the user the protocol number instead
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

def udp_sprays(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message, ("%s" % ip,65212))
        except:
            pass
# The difference between Windows and Linux is that Windows will
# allow us to sniff all incoming packets regardless of protocol,
# whereas Linux forces us to specify that we are sniffing ICMP.
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))

# catch the packet headers (HRDINCL -> Header include. Duh.)
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# turn on promiscuous mode for windows
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

thread = threading.Thread(target=udp_sprays, args=(subnet, magic_message))
thread.start()

# read in packets
try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]

        ip_header = IP(raw_buffer[0:20])

        print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

        if ip_header.protocol == "ICMP":
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            icmp_header = ICMP(buf)
            print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)
            if icmp_header.code == 3 and icmp_header.type == 3:
                if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                    print "Host Up: %s" % ip_header.src_address
except KeyboardInterrupt:
    # turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
