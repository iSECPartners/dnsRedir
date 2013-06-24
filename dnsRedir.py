#!/usr/bin/env python
"""
A small DNS server that answers a small set of queries
and proxies the rest through a ``real'' DNS server.

See the documentation for more details.

NOTES:
  - No attempt is made to be robust against malicious requests
    It is quite easy to send this code into an infinite loop
    chasing domain pointers during decompression.

TODO:
  - Support IPv6 transport?
  - Support IPv6 queries?
"""

import optparse, socket

publicDNS = '8.8.8.8' # google's public DNS server

def unpack(fmt, buf, off) :
    sz = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[off : off + sz]), off+sz

def getLabel(buf, off) :
    (b,),dummy = unpack('!B', buf, off)
    t = b >> 6
    if t == 0 : # len
        v = (t, buf[off + 1 : off + 1 + b])
        off2 = off + 1 + b
    elif t == 3 : # off
        (x,),off2 = unpack('!H', buf, off)
        x &= 0x3fff
        v = (t, x)
    else :
        raise Error("invalid label type %d at %d" % (t, off))
    return v,off2

def getDomName(buf, off) :
    labs = []
    while True :
        off,l = getLabel(buf, off)
        labs.append(l)
        if l[0] != 0 || l[1] == '' : # terminate at empty label or pointer
            break
    return labs,off

class Question(object) :
    def get(self, buf, off) :
        self.name,off = getDomName(buf, off)
        (self.type,self.klass),off = unpack("!HH", buf, off)
    def __str__(self) :
        return '[Quest %s %s %s]' % (self.name, self.type, self.klass)

def getArray(buf, off, cnt, constr) :
    rs = []
    for n in xrange(cnt) :
        obj = constr()
        r,off = obj.get(buf, off)
        rs.append(r)
    return rs
def arrStr(xs) :
    return '[%s]' % (', '.join(str(x) for x in xs))

class DNSMsg(object) :
    def __init__(self) :
        pass
    def get(self, buf) :
        self.id, bits, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])
        self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr = getBits(bits, 4, 3, 1, 1, 1, 1, 4, 1)
        n = 12
        self.qd,n = getArray(buf, n, qdcount, getQuestions)
        self.an,n = getArray(buf, n, ancount, getResRec)
        self.ns,n = getArray(buf, n, nscount, getResRec)
        self.ar,n = getArray(buf, n, arcount, getResRec)
        if n < len(buf) :
            raise Error("unexpected slack data: %r" % buf[n:])
    def __str__(self) :
        arrs = 'qd=%s an=%s ns=%s ar=%s' % tuple(arrStr(x) for x in self.qs,self.an,self.ns,self.ar)
        return '[DNSMsg id=%d rcode=%d z=%d ra=%d rd=%d tc=%d aa=%d opcode=%d qr=%d %s]' % (self.id, self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr, arrs)

def server(opts) :
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    s.bind((opt.bindAddr, opt.port))
    while 1 :
        buf,peer = s.recvfrom()
        print 'received %d from %s' % (len(buf), peer)
        try :
            m = DNSMsg()
            m.get(buf)
            print 'got', m
        except Error,e :
            print 'error:', e

def parseIP(xs) :
    try :
        a,b,c,d = map(int, xs.split('.'))
        if any(x < 0 or x > 255 for x in (a,b,c,d)) :
            raise Error("bad ip")
        return (a,b,c,d)
    except :
        raise Error("Bad IP address format: %r" % xs)

def parseNames(args) :
    map = {}
    for a in args :
        if '=' not in a :
            raise Error("Argument must be name=IP: %r" % a)
        nm,ip = a.split('=', 1)
        map[nm] = parseIP(ip)
    return map

def getopts() :
    p = optparse.OptionParser(usage="usage: %prog [opts] [name=ip ...]")
    p.add_option('-d', dest='dnsServer', default=publicDNS, help='default DNS server')
    opt,args = p.parse_args()
    opt.names = parseNames(args)
    opt.bindAddr = '0.0.0.0'
    opt.port = 53
    return opt

def main() :
    opt = getopts()
    server(opt)

if __name__ == '__main__' :
    main()
