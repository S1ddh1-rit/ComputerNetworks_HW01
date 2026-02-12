"""
pktsniffer.py

A packet analysis tool that reads packets from an offline PCAP file
and displays Ethernet, IP, and transport-layer header information.

Supported protocols:
- TCP
- UDP
- ICMP

The program supports:
- Limiting the number of packets using -c
- Filtering packets using BPF filters
"""

import argparse
from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP


def print_ethernet(pkt):
    """
    Print Ethernet header information.

    Args:
        pkt: A Scapy packet object.
    """
    if Ether not in pkt:
        return
    eth = pkt[Ether]
    print("         Ethernet Header")
    print(f"Packet size: {len(pkt)} bytes")
    print(f"Dest MAC address: {eth.dst}")
    print(f"Source MAC address:      {eth.src}")
    print(f"Ethertype:               0x{eth.type:04x}")


def print_ip(pkt):
    """
    Print IP header information.

    Args:
        pkt: A Scapy packet object.
    """
    if IP not in pkt:
        return
    ip = pkt[IP]
    print("         IP Header:")
    print(f"Version:            {ip.version}")
    print(f"Header length:      {ip.ihl * 4} bytes")
    print(f"Type of service:    {ip.tos}")
    print(f"Total length:       {ip.len}")
    print(f"Identification:     {ip.id}")
    print(f"Flags:              {ip.flags}")
    print(f"Fragment offset:    {ip.frag}")
    print(f"TTL:       {ip.ttl}")
    print(f"Protocol:           {ip.proto}")
    print(f"Header checksum:    {hex(ip.chksum)}")
    print(f"ource IP address:  {ip.src}")
    print(f"Dest IP address:    {ip.dst}")


def print_tcp(pkt):
    """
    Print TCP header information.

    Args:
        pkt: A Scapy packet object.
    """
    if TCP not in pkt:
        return
    tcp = pkt[TCP]
    print("         TCP Header:")
    print(f"Source port:        {tcp.sport}")
    print(f"Dest port:   {tcp.dport}")
    print(f"Sequence number:    {tcp.seq}")
    print(f"Acknowledgment:     {tcp.ack}")
    print(f"Flags:              {tcp.flags}")
    print(f"Window size:        {tcp.window}")


def print_udp(pkt):
    """
    Print UDP header information.

    Args:
        pkt: A Scapy packet object.
    """

    if UDP not in pkt:
        return
    udp = pkt[UDP]
    print("         UDP Header:")
    print(f"Source port:        {udp.sport}")
    print(f"Dest port:   {udp.dport}")
    print(f"Length:             {udp.len}")
    print(f"Checksum:           {hex(udp.chksum)}")


def print_icmp(pkt):
    """
    Print ICMP header information.

    Args:
        pkt: A Scapy packet object.
    """
    icmp = pkt[ICMP]
    print("         ICMP Header:")
    print(f"Type:               {icmp.type}")
    print(f"Code:               {icmp.code}")
    print(f"Checksum:           {hex(icmp.chksum)}")



def main():
    """
    Main program entry point.

    Parses command-line arguments, reads packets from a PCAP file,
    and prints header information for each packet.
    """
    parser = argparse.ArgumentParser(prog="pktsniffer")
    parser.add_argument("-r", required=True)
    parser.add_argument("-c", type=int, default=0)
    parser.add_argument("filter", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    bpf_filter = None
    if args.filter:
        bpf_filter = " ".join(args.filter)

    #list of packets
    packets = sniff(offline=args.r,filter=bpf_filter,store=True)

    # Apply packet limit manually
    if args.c > 0:
        packets = packets[:args.c]

    for i, pkt in enumerate(packets, start=1):
        print()
        print(f"Packet {i}")
        print_ethernet(pkt)
        print_ip(pkt)

        if TCP in pkt:
            print_tcp(pkt)
        elif UDP in pkt:
            print_udp(pkt)
        elif ICMP in pkt:
            print_icmp(pkt)
    print()
    print(f"Total packets analyzed: {len(packets)}")


if __name__ == "__main__":
    main()
