from scapy.all import *

my_ip = "127.0.0.10"
server_ip = "127.0.0.20"

sport = 65533
dport = 8080
ip = IP(dst=server_ip, src=my_ip)

# syn
syn = ip / TCP(flags='S', sport=sport, dport=dport)
print "SENDING SYN"
syn_ack = sr1(syn)
print "RECEIVED synack"
print syn_ack

# data
data = 'GET / HTTP/1.1\r\nHost: farts.farts\r\n\r\n'
request = ip / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A') / data
reply = sr1(request)

print reply
