from FakeTCP import FakeTCP
from scapy.all import *

my_ip = "127.0.0.10"
server_ip = "127.0.0.20"

sport = 65533
dport = 8080
ip = IP(dst=server_ip, src=my_ip)

# syn
syn = ip / FakeTCP(flags='S', sport=sport, dport=dport)
print "SENDING SYN"
send(syn)
#print "RECEIVED synack"
#print syn_ack

# data
data = 'GET / HTTP/1.1\r\nHost: reversed.tcp\r\n\r\n'
request = ip / FakeTCP(dport=dport, sport=sport, seq=syn[FakeTCP].seq+1, ack=0xdeadbeef + 1, flags='A') / data
reply = sr1(request)

print reply
