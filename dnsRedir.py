#!/usr/bin/env python
"""
A small DNS server that answers a small set of queries
and proxies the rest through a ``real'' DNS server.

See the documentation for more details.

TODO:
  - Support IPv6 transport?
  - Support IPv6 queries?
"""

import optparse, socket, struct

publicDNS = '8.8.8.8' # google's public DNS server

class Error(Exception) :
    pass

def getBits(num, *szs) :
    rs = []
    for sz in szs :
        mask = (1 << sz) - 1
        rs.append(num & mask)
        num >>= sz
    return rs

def unpack(fmt, buf, off) :
    sz = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[off : off + sz]), off+sz

def getLabel(buf, off, ctx) :
    (b,),dummy = unpack('!B', buf, off)
    t = b >> 6
    if t == 0 : # len
        v = (t, buf[off + 1 : off + 1 + b], off)
        off2 = off + 1 + b
    elif t == 3 : # off
        (x,),off2 = unpack('!H', buf, off)
        x &= 0x3fff
        v = (t, x, off)
    else :
        raise Error("invalid label type %d at %d" % (t, off))
    return v,off2

def getDomName(buf, off, ctx) :
    idx = off
    labs = []
    while True :
        l,off = getLabel(buf, off, ctx)
        labs.append(l)
        if l[0] != 0 or l[1] == '' : # terminate at empty label or pointer
            break

    if idx not in ctx : # decompress
        ctx[idx] = None
        r = []
        for t,v,o in labs :
            if t == 0 :
                r.append(v)
            else :
                name,dummy = getDomName(buf, v, ctx)
                r.append(name)
        ctx[idx] = '.'.join(r)
    if ctx[idx] is None :
        raise Error("invalid loop in domain decompression at %d" % o)
    return ctx[idx],off

class Question(object) :
    def __init__(self, ctx) :
        self.ctx = ctx
    def get(self, buf, off) :
        self.name,off = getDomName(buf, off, self.ctx)
        (self.type,self.klass),off = unpack("!HH", buf, off)
        return off
    def __str__(self) :
        return '[Quest %s %s %s]' % (self.name, self.type, self.klass)

class ResRec(object) :
    def __init__(self, ctx) :
        self.ctx = ctx
    def get(self, buf, off) :
        self.name,off = getDomName(buf, off, self.ctx)
        (self.type,self.klass,self.ttl, l),off = unpack("!HHIH", buf, off)
        self.nested = buf[off : off + l] # XXX
        off += l 
        return off 
    def __str__(self) :
        return '[ResRec %s %s %s %s %r]' % (self.name, self.type, self.klass, self.ttl, self.nested)

def getArray(buf, off, cnt, constr, *args) :
    objs = []
    for n in xrange(cnt) :
        obj = constr(*args)
        off = obj.get(buf, off)
        objs.append(obj)
    return objs, off

def arrStr(xs) :
    return '[%s]' % (', '.join(str(x) for x in xs))

class DNSMsg(object) :
    def get(self, buf) :
        self.ctx = {}
        self.id, bits, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])
        self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr = getBits(bits, 4, 3, 1, 1, 1, 1, 4, 1)
        n = 12
        self.qd,n = getArray(buf, n, qdcount, Question, self.ctx)
        self.an,n = getArray(buf, n, ancount, ResRec, self.ctx)
        self.ns,n = getArray(buf, n, nscount, ResRec, self.ctx)
        self.ar,n = getArray(buf, n, arcount, ResRec, self.ctx)
        if n < len(buf) :
            raise Error("unexpected slack data: %r" % buf[n:])

    def __str__(self) :
        arrs = 'qd=%s an=%s ns=%s ar=%s' % tuple(arrStr(x) for x in (self.qd,self.an,self.ns,self.ar))
        return '[DNSMsg id=%d rcode=%d z=%d ra=%d rd=%d tc=%d aa=%d opcode=%d qr=%d %s]' % (self.id, self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr, arrs)

def testParse() :
    buf = '\x85%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x03foo\x03bar\x00\x00\x01\x00\x01'
    buf = '''da12 8180
     0001 0008 0000 000a 0874 6865 6e65 7773
     6803 636f 6d00 00ff 0001 c00c 0001 0001
     0001 386a 0004 48eb c992 c00c 0002 0001
     0001 50e7 000c 036e 7333 0268 6503 6e65
     7400 c00c 0002 0001 0001 50e7 0006 036e
     7332 c03e c00c 0002 0001 0001 50e7 0006
     036e 7331 c03e c00c 0002 0001 0001 50e7
     0006 036e 7334 c03e c00c 0002 0001 0001
     50e7 0006 036e 7335 c03e c00c 0006 0001
     0001 50e7 0023 c064 0a68 6f73 746d 6173
     7465 72c0 3e77 fc96 1900 002a 3000 0007
     0800 093a 8000 0151 80c0 0c00 0f00 0100
     0150 e700 2700 0102 6d78 0874 6865 6e65
     7773 6803 636f 6d04 6375 7374 0162 0b68
     6f73 7465 6465 6d61 696c c015 c03a 0001
     0001 0000 8abf 0004 d8da 8402 c03a 001c
     0001 0000 167a 0010 2001 0470 0300 0000
     0000 0000 0000 0002 c052 0001 0001 0000
     1178 0004 d8da 8302 c052 001c 0001 0000
     1677 0010 2001 0470 0200 0000 0000 0000
     0000 0002 c064 0001 0001 0000 1a98 0004
     d8da 8202 c076 0001 0001 0000 1677 0004
     d842 0102 c076 001c 0001 0000 d5c1 0010
     2001 0470 0400 0000 0000 0000 0000 0002
     c088 0001 0001 0000 be49 0004 d842 5012
     c088 001c 0001 0000 d5c1 0010 2001 0470
     0500 0000 0000 0000 0000 0002 c0cb 0001
     0001 0000 0d77 0004 4062 2404'''.replace('\n','').replace(' ','').decode('hex')

    m = DNSMsg()
    m.get(buf)
    print m
    return

def server(opt) :
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    s.bind((opt.bindAddr, opt.port))
    while 1 :
        buf,peer = s.recvfrom(64 * 1024)
        print 'received %d from %s' % (len(buf), peer)
        try :
            m = DNSMsg()
            m.get(buf)
            print 'got', m
            print m.decomp(m.qd[0].name)
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
    #server(opt)
    testParse()

if __name__ == '__main__' :
    main()
