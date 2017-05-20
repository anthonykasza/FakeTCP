from scapy.all import *

''' ip = IP()
tcp = TCP()
ls(tcp)
sport    : ShortEnumField     = 20        (20)
dport    : ShortEnumField     = 80        (80)
seq    : IntField       = 0         (0)
ack    : IntField       = 0         (0)
dataofs  : BitField       = None      (None)
reserved   : BitField       = 0         (0)
flags    : FlagsField       = 2         (2)
window   : ShortField       = 8192      (8192)
chksum   : XShortField      = None      (None)
urgptr   : ShortField       = 0         (0)
options  : FakeTCPOptionsField    = {}        ({})
'''


FakeTCPOptions = (
              { 0 : ("EOL",None),
                1 : ("NOP",None),
                2 : ("MSS","!H"),
                3 : ("WScale","!B"),
                4 : ("SAckOK",None),
                5 : ("SAck","!"),
                8 : ("Timestamp","!II"),
                14 : ("AltChkSum","!BH"),
                15 : ("AltChkSumOpt",None),
                25 : ("Mood","!p"),
                28 : ("UTO", "!H"),
                34 : ("TFO", "!II"),
                # RFC 3692
                253 : ("Experiment","!HHHH"),
                254 : ("Experiment","!HHHH"),
                },
              { "EOL":0,
                "NOP":1,
                "MSS":2,
                "WScale":3,
                "SAckOK":4,
                "SAck":5,
                "Timestamp":8,
                "AltChkSum":14,
                "AltChkSumOpt":15,
                "Mood":25,
                "UTO":28,
                "TFO":34,
                } )

class FakeTCPOptionsField(StrField):
  islist=1
  def getfield(self, pkt, s):
    opsz = 0
#    opsz = (pkt.dataofs-5)*4
    if opsz < 0:
      warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
      opsz = 0
    return s[opsz:],self.m2i(pkt,s[:opsz])
  def m2i(self, pkt, x):
    opt = []
    while x:
      onum = ord(x[0])
      if onum == 0:
        opt.append(("EOL",None))
        x=x[1:]
        break
      if onum == 1:
        opt.append(("NOP",None))
        x=x[1:]
        continue
      olen = ord(x[1])
      if olen < 2:
        warning("Malformed TCP option (announced length is %i)" % olen)
        olen = 2
      oval = x[2:olen]
      if TCPOptions[0].has_key(onum):
        oname, ofmt = TCPOptions[0][onum]
        if onum == 5: #SAck
          ofmt += "%iI" % (len(oval)/4)
        if ofmt and struct.calcsize(ofmt) == len(oval):
          oval = struct.unpack(ofmt, oval)
          if len(oval) == 1:
            oval = oval[0]
        opt.append((oname, oval))
      else:
        opt.append((onum, oval))
      x = x[olen:]
    return opt
  
  def i2m(self, pkt, x):
    opt = ""
    for oname,oval in x:
      if type(oname) is str:
        if oname == "NOP":
          opt += b"\x01"
          continue
        elif oname == "EOL":
          opt += b"\x00"
          continue
        elif TCPOptions[1].has_key(oname):
          onum = TCPOptions[1][oname]
          ofmt = TCPOptions[0][onum][1]
          if onum == 5: #SAck
            ofmt += "%iI" % len(oval)
          if ofmt is not None and (type(oval) is not str or "s" in ofmt):
            if type(oval) is not tuple:
              oval = (oval,)
            oval = struct.pack(ofmt, *oval)
        else:
          warning("option [%s] unknown. Skipped."%oname)
          continue
      else:
        onum = oname
        if type(oval) is not str:
          warning("option [%i] is not string."%onum)
          continue
      opt += chr(onum)+chr(2+len(oval))+oval
    return opt+b"\x00"*(3-((len(opt)+3)%4))
  def randval(self):
    return [] # XXX


class FakeTCP(Packet):
  name = "FakeTCP"
  # NOTE: These are the exact same as scapy's default TCP class
  #       except the order of the fields are in reverse
  fields_desc = [
                 FakeTCPOptionsField("options", []),
                 ShortField("urgptr", 0),
                 XShortField("chksum", None),
                 ShortField("window", 8192),
                 FlagsField("flags", 0x2, 9, "FSRPAUECN"),
                 BitField("reserved", 0, 3),
                 BitField("dataofs", None, 4),
                 IntField("ack", 0),
                 IntField("seq", 0),
                 ShortEnumField("dport", 80, TCP_SERVICES),
                 ShortEnumField("sport", 20, TCP_SERVICES),
               ]
  def post_build(self, p, pay):
    p += pay
    dataofs = self.dataofs
    if dataofs is None:
      dataofs = 5+((len(self.get_field("options").i2m(self,self.options))+3)/4)
      p = p[:12]+chr((dataofs << 4) | ord(p[12])&0x0f)+p[13:]
    if self.chksum is None:
      if isinstance(self.underlayer, IP):
        if self.underlayer.len is not None:
          if self.underlayer.ihl is None:
            olen = sum(len(x) for x in self.underlayer.options)
            ihl = 5 + olen / 4 + (1 if olen % 4 else 0)
          else:
            ihl = self.underlayer.ihl
          ln = self.underlayer.len - 4 * ihl
        else:
          ln = len(p)
        psdhdr = struct.pack("!4s4sHH",
                   inet_aton(self.underlayer.src),
                   inet_aton(self.underlayer.dst),
                   self.underlayer.proto,
                   ln)
        ck=checksum(psdhdr+p)
        p = p[:16]+struct.pack("!H", ck)+p[18:]
      elif conf.ipv6_enabled and isinstance(self.underlayer, scapy.layers.inet6.IPv6) or isinstance(self.underlayer, scapy.layers.inet6._IPv6ExtHdr):
        ck = scapy.layers.inet6.in6_chksum(socket.IPPROTO_TCP, self.underlayer, p)
        p = p[:16]+struct.pack("!H", ck)+p[18:]
      else:
        warning("No IP underlayer to compute checksum. Leaving null.")
    return p
  def hashret(self):
    if conf.checkIPsrc:
      return struct.pack("H",self.sport ^ self.dport)+self.payload.hashret()
    else:
      return self.payload.hashret()
  def answers(self, other):
    if not isinstance(other, FakeTCP):
      return 0
    # RST packets don't get answers
    if other.flags.R:
      return 0
    # We do not support the four-way handshakes with the SYN+ACK
    # answer split in two packets (one ACK and one SYN): in that
    # case the ACK will be seen as an answer, but not the SYN.
    if self.flags.S:
      # SYN packets without ACK are not answers
      if not self.flags.A:
        return 0
      # SYN+ACK packets answer SYN packets
      if not other.flags.S:
        return 0
    if conf.checkIPsrc:
      if not ((self.sport == other.dport) and
          (self.dport == other.sport)):
        return 0
    # Do not check ack value for SYN packets without ACK
    if not (other.flags.S and not other.flags.A) \
       and abs(other.ack - self.seq) > 2:
      return 0
    # Do not check ack value for RST packets without ACK
    if self.flags.R and not self.flags.A:
      return 1
    if abs(other.seq - self.ack) > 2 + len(other.payload):
      return 0
    return 1
  def mysummary(self):
    if isinstance(self.underlayer, IP):
      return self.underlayer.sprintf("FakeTCP %IP.src%:%FakeTCP.sport% > %IP.dst%:%FakeTCP.dport% %FakeTCP.flags%")
    elif conf.ipv6_enabled and isinstance(self.underlayer, scapy.layers.inet6.IPv6):
      return self.underlayer.sprintf("FakeTCP %IPv6.src%:%FakeTCP.sport% > %IPv6.dst%:%FakeTCP.dport% %FakeTCP.flags%")
    else:
      return self.sprintf("FakeTCP %FakeTCP.sport% > %FakeTCP.dport% %FakeTCP.flags%")


TCPOptions = (
        { 0 : ("EOL",None),
        1 : ("NOP",None),
        2 : ("MSS","!H"),
        3 : ("WScale","!B"),
        4 : ("SAckOK",None),
        5 : ("SAck","!"),
        8 : ("Timestamp","!II"),
        14 : ("AltChkSum","!BH"),
        15 : ("AltChkSumOpt",None),
        25 : ("Mood","!p"),
        28 : ("UTO", "!H"),
        34 : ("TFO", "!II"),
        # RFC 3692
        253 : ("Experiment","!HHHH"),
        254 : ("Experiment","!HHHH"),
        },
        { "EOL":0,
        "NOP":1,
        "MSS":2,
        "WScale":3,
        "SAckOK":4,
        "SAck":5,
        "Timestamp":8,
        "AltChkSum":14,
        "AltChkSumOpt":15,
        "Mood":25,
        "UTO":28,
        "TFO":34,
        } )

class FakeTCPOptionsField(StrField):
  islist=1
  def getfield(self, pkt, s):
    opsz = (pkt.dataofs-5)*4
    if opsz < 0:
      warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
      opsz = 0
    return s[opsz:],self.m2i(pkt,s[:opsz])
  def m2i(self, pkt, x):
    opt = []
    while x:
      onum = ord(x[0])
      if onum == 0:
        opt.append(("EOL",None))
        x=x[1:]
        break
      if onum == 1:
        opt.append(("NOP",None))
        x=x[1:]
        continue
      olen = ord(x[1])
      if olen < 2:
        warning("Malformed FakeTCP option (announced length is %i)" % olen)
        olen = 2
      oval = x[2:olen]
      if TCPOptions[0].has_key(onum):
        oname, ofmt = TCPOptions[0][onum]
        if onum == 5: #SAck
          ofmt += "%iI" % (len(oval)/4)
        if ofmt and struct.calcsize(ofmt) == len(oval):
          oval = struct.unpack(ofmt, oval)
          if len(oval) == 1:
            oval = oval[0]
        opt.append((oname, oval))
      else:
        opt.append((onum, oval))
      x = x[olen:]
    return opt
  
  def i2m(self, pkt, x):
    opt = ""
    for oname,oval in x:
      if type(oname) is str:
        if oname == "NOP":
          opt += b"\x01"
          continue
        elif oname == "EOL":
          opt += b"\x00"
          continue
        elif TCPOptions[1].has_key(oname):
          onum = TCPOptions[1][oname]
          ofmt = TCPOptions[0][onum][1]
          if onum == 5: #SAck
            ofmt += "%iI" % len(oval)
          if ofmt is not None and (type(oval) is not str or "s" in ofmt):
            if type(oval) is not tuple:
              oval = (oval,)
            oval = struct.pack(ofmt, *oval)
        else:
          warning("option [%s] unknown. Skipped."%oname)
          continue
      else:
        onum = oname
        if type(oval) is not str:
          warning("option [%i] is not string."%onum)
          continue
      opt += chr(onum)+chr(2+len(oval))+oval
    return opt+b"\x00"*(3-((len(opt)+3)%4))
  def randval(self):
    return [] # XXX


bind_layers( IP,            FakeTCP,           frag=0, proto=99)
conf.stats_classic_protocols += [FakeTCP]
conf.stats_dot11_protocols += [FakeTCP]
