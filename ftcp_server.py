from FakeTCP import FakeTCP
from scapy.all import *
from time import *
from random import *

server_ip = "127.0.0.20"
client_ip = "127.0.0.10"
interface = "lo"
filter = "ip dst " + server_ip + " and not ip src " + server_ip
half_open = []

def watch_for_it(pkt):
  print "RECEIVED PACKET"

  # SYN pkt handling
  if FakeTCP in pkt and pkt[FakeTCP].flags == 2:
    print "received syn, sending synack"
    seqnum = randint(1, 4294967295)
    half_open.append({'time': time(), 'src': client_ip, 'sport': pkt[IP].sport, 'dport': pkt[FakeTCP].dport, 'seqnum': seqnum})
    p=IP(dst=client_ip, src=server_ip)/FakeTCP(dport=pkt[FakeTCP].sport, sport=pkt[FakeTCP].dport, ack=pkt[FakeTCP].seq+1, seq=seqnum, flags="SA")
    return send(p)
  # ACK pkt handling
  elif FakeTCP in pkt and pkt[FakeTCP].flags in (16, 24, 48):
    print "received data, sending data"
    for conn in half_open:
      data = "200 OK HTTP/1.1\r\n\Server: reversed.tcp\n\r\n\rThe flag takes the shape of '[source_ip]_[source_port]_[dest_ip]_[dest_port]'"
      p=IP(dst=client_ip, src=server_ip)/FakeTCP(dport=pkt[FakeTCP].sport, sport=pkt[FakeTCP].dport, ack=pkt[FakeTCP].seq+1, seq=0xdeadbeef, flags="AP") / data
      return send(p)
  # All other pkt handling
  else:
    print "FUCK THAT PACKET"
    return

sniff(filter=filter, iface=interface, count=0, prn=watch_for_it)
