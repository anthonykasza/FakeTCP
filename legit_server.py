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
  if TCP in pkt and pkt[TCP].flags == 2:
    print "received syn, sending synack"
    seqnum = randint(1, 4294967295)
    half_open.append({'time': time(), 'src': client_ip, 'sport': pkt[IP].sport, 'dport': pkt[TCP].dport, 'seqnum': seqnum})
    p=IP(dst=client_ip, src=server_ip)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=seqnum, flags="SA")
    return send(p)
  # ACK pkt handling
  elif TCP in pkt and pkt[TCP].flags in (16, 24, 48):
    print "received data, sending data"
    for conn in half_open:
      data = "200 OK HTTP/1.1\r\n\r\n"
      p=IP(dst=client_ip, src=server_ip)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=pkt[TCP].ack, flags="AP") / data
      return send(p)
  # All other pkt handling
  else:
    print "FUCK THAT PACKET"
    return

sniff(filter=filter, iface=interface, count=0, prn=watch_for_it)
