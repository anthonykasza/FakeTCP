from scapy.all import *
from FakeTCP import FakeTCP

ip = IP()
print "IP"
print ls(ip)
print

tcp = TCP()
print "TCP"
print ls(tcp)
print

fake_tcp = FakeTCP()
print "FakeTCP"
print ls(fake_tcp)
print
