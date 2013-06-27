#!/usr/bin/env python
"""
A small DNS server that answers a small set of queries
and proxies the rest through a 'real' DNS server.

See the documentation for more details.

NOTES:
  - no attempt is made to make IDs unguessable.  This is a security
    weakness that can be exploited in a hostile enviornment.
TODO:
  - Support IPv6 queries?
"""

import optparse, re, socket, struct, time

publicDNS = '8.8.8.8' # google's public DNS server

A,NS,CNAME,PTR,MX,TXT = 1,2,5,12,15,16
IN = 1

class Error(Exception) :
    pass

def getBits(num, *szs) :
    rs = []
    for sz in szs :
        mask = (1 << sz) - 1
        rs.append(num & mask)
        num >>= sz
    return rs
def putBits(szs, *args) :
    num = 0
    sh = 0
    for (sz,a) in zip(szs, args) :
        mask = (1 << sz) - 1
        num |= ((a & mask) << sh)
        sh += sz
    return num

def unpack(fmt, buf, off) :
    sz = struct.calcsize(fmt)
    return struct.unpack(fmt, buf[off : off + sz]), off+sz
def pack(buf, fmt, *args) :
    buf.append(struct.pack(fmt, *args))

def getLabel(buf, off, ctx) :
    """Get a DNS label, without any decompression."""
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
    """Get a domain name, performing decompression."""
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

def putDomain(buf, dom) :
    """Put a domain name. Never compressed..."""
    labs = dom.rstrip('.').split('.')
    if len(dom) > 255 or any(len(l) > 63 or len(l) == 0 for l in labs) :
        raise Error("Cannot encode domain: %s" % dom)
    labs.append('')
    for l in labs :
        pack(buf, "!B", len(l))
        buf.append(l)

class DNSQuestion(object) :
    def get(self, buf, off, ctx) :
        self.name,off = getDomName(buf, off, ctx)
        (self.type,self.klass),off = unpack("!HH", buf, off)
        return off
    def put(self, buf) :
        putDomain(buf, self.name)
        pack(buf, "!HH", self.type, self.klass)
    def __str__(self) :
        return '[Quest %s %s %s]' % (self.name, self.type, self.klass)

class ResA(object) :
    def __init__(self, val=None) :
        if val is not None :
            self.val = val
    def get(self, buf, off) :
        self.val = mkIP(buf[off : off+4])
        return off+4
    def put(self, buf) :
        buf.append(parseIP(self.val))
    def __str__(self) :
        return '[A %s]' % (self.val)

class DNSResRec(object) :
    children = {
        A:      ResA,
        #CNAME:  ResCName,
        #MX:     ResMx,
        #NS:     ResNs,
        #PTR:    ResPtr,
        #TXT:    ResTxt,
    }
    def get(self, buf, off, ctx) :
        self.name,off = getDomName(buf, off, ctx)
        (self.type,self.klass,self.ttl, l),off = unpack("!HHIH", buf, off)
        self.nested = buf[off : off + l] 
        off += l 

        self.val = None
        if self.type in self.children :
            self.val = self.children[self.type]()
            n = self.val.get(self.nested, 0)
            if n != len(self.nested) :
                raise Error("unexpected slack data: %r" % self.nested[n:])
        return off 

    def put(self, buf) :
        if self.val is not None :
            buf2 = []
            self.val.put(buf2)
            self.nested = ''.join(buf2)

        putDomain(buf, self.name)
        l = len(self.nested)
        pack(buf, "!HHIH", self.type, self.klass, self.ttl, l)
        buf.append(self.nested)

    def __str__(self) :
        if self.val :
            return '[RR %s %s %s %s %s]' % (self.type, self.klass, self.ttl, self.name, self.val)
        else :
            return '[RR %s %s %s %s %r]' % (self.type, self.klass, self.ttl, self.name, self.nested)

def getArray(buf, off, cnt, constr, ctx) :
    objs = []
    for n in xrange(cnt) :
        obj = constr()
        off = obj.get(buf, off, ctx)
        objs.append(obj)
    return objs, off
def putArray(buf, arr) :
    for obj in arr :
        obj.put(buf)
def arrStr(xs) :
    return '[%s]' % (', '.join(str(x) for x in xs))

class DNSMsg(object) :
    def __init__(self, buf=None) :
        if buf is not None :
            self.get(buf)
    def get(self, buf) :
        ctx = {}
        self.id, bits, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])
        self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr = getBits(bits, 4, 3, 1, 1, 1, 1, 4, 1)
        n = 12
        self.qd,n = getArray(buf, n, qdcount, DNSQuestion, ctx)
        self.an,n = getArray(buf, n, ancount, DNSResRec, ctx)
        self.ns,n = getArray(buf, n, nscount, DNSResRec, ctx)
        self.ar,n = getArray(buf, n, arcount, DNSResRec, ctx)
        if n < len(buf) :
            raise Error("unexpected slack data: %r" % buf[n:])
    def put(self) :
        buf = []
        bits = putBits((4,3,1,1,1,1,1,1,4,1), self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr)
        pack(buf, "!HHHHHH", self.id, bits, len(self.qd), len(self.an), len(self.ns), len(self.ar))
        putArray(buf, self.qd)
        putArray(buf, self.an)
        putArray(buf, self.ns)
        putArray(buf, self.ar)
        bytes = ''.join(buf)
        if len(bytes) > 64*1024 :
            raise Error("Response is too big: %d!" % len(bytes))
        return bytes

    def __str__(self) :
        arrs = 'qd=%s an=%s ns=%s ar=%s' % tuple(arrStr(x) for x in (self.qd,self.an,self.ns,self.ar))
        return '[DNSMsg id=%d rcode=%d z=%d ra=%d rd=%d tc=%d aa=%d opcode=%d qr=%d %s]' % (self.id, self.rcode, self.z, self.ra, self.rd, self.tc, self.aa, self.opcode, self.qr, arrs)

def findMatch(opt, ty, name) :
    for ty_,pat,val in opt.names :
        if ty == ty_ and re.match(pat, name) :
            return val

def answer(q, val, ttl, id, opcode) :
    a = DNSResRec()
    a.name = q.name
    a.type = q.type
    a.klass = q.klass
    a.ttl = ttl
    a.val = val
    
    resp = DNSMsg()
    resp.id = id
    resp.qr = 1
    resp.opcode = opcode
    resp.aa = 0
    resp.tc = 0
    resp.rd = 0
    resp.ra = 0
    resp.z = 0
    resp.rcode = 0
    resp.qd = [q]
    resp.an = [a]
    resp.ns = []
    resp.ar = []
    return resp

def procQuery(opt, s, m, peer) :
    resp = None
    if m.opcode == 0 and len(m.qd) == 1 and m.qd[0].type == A and m.qd[0].klass == IN :
        q = m.qd[0]
        ip = findMatch(opt, 'a', q.name)
        if ip :
            resp = answer(q, ResA(ip), opt.ttl, m.id, m.opcode)
    return resp

class Proxy(object) :
    """Proxy objects and the global proxy table."""
    timeo = 30
    id = 1
    tab = {}
    def __init__(self, peer, msg) :
        self.expire = time.time() + self.timeo
        self.peer = peer
        self.origId = msg.id
        self.id = Proxy.id

        if self.id in self.tab :
            # should only happen in hostile situations or under heavy loads
            raise Error("proxy ID collision!")
        self.tab[self.id] = self

        Proxy.id = (Proxy.id + 1) & 0xffff # weak ID generation

    @staticmethod
    def clean() :
        self = Proxy
        now = time.time()
        for k,v in self.tab.items() :
            if v.expire <= now :
                print 'expire', k
                del self.tab[k]

def sendMsg(s, addr, msg) :
    return s.sendto(msg.put(), addr)

def procMsg(opt, s, buf, peer) :
    Proxy.clean()

    m = DNSMsg()
    m.get(buf)
    resp = None
    if m.qr == 0 : # query from client - answer it or proxy it
        resp = procQuery(opt, s, m, peer)
        if resp is not None : 
            print "send answer to", peer
            sendMsg(s, peer, resp)
        else : # not processed, proxy it
            p = Proxy(peer, m)
            m.id = p.id
            print "proxy msg to server from", peer
            srv = opt.dnsServer, opt.dnsServerPort
            sendMsg(s, srv, m)
    else : # response from server - proxy back to client
        p = Proxy.tab.get(m.id)
        if p is not None :
            del Proxy.tab[m.id]
            m.id = p.origId
            print "proxy msg from server %s to client %s" % (peer, p.peer)
            sendMsg(s, p.peer, m)
        else : 
            print "%s: unexpected response %d" % (peer, m.id)

def server(opt) :
    if opt.six :
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) 
    else :
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        try :
            # Handle both ipv4 and ipv6. 
            # This is on by default on many but not all systems.
            s.setsockopt(socket.IPPROTO_IPV6, IPV6_V6ONLY, 0)
        except Exception, e :
            pass
    s.bind((opt.bindAddr, opt.port))
    while 1 :
        buf,peer = s.recvfrom(64 * 1024)
        print 'received %d from %s' % (len(buf), peer)
        try :
            procMsg(opt, s, buf, peer)
        except Error,e :
            print 'error:', e

def mkIP(xs) :
    return '.'.join('%d' % ord(x) for x in xs)
def parseIP(xs) :
    try :
        a,b,c,d = map(int, xs.split('.'))
        if any(x < 0 or x > 255 for x in (a,b,c,d)) :
            raise Error("bad ip")
        return ''.join(chr(x) for x in (a,b,c,d))
    except :
        raise Error("Bad IP address format: %r" % xs)

def parseNames(args) :
    map = []
    for a in args :
        ws = a.split(":")
        if len(ws) != 3 :
            raise Error("Argument must be type:name:value -- %r" % a)
        ty,nm,val = ws
        if ty == 'a' :
            dummy = parseIP(val)
        else :
            raise Error("Unsupported query type %r in %r" % (ty, a))
        map.append((ty,nm,val))
    return map

def getopts() :
    p = optparse.OptionParser(usage="usage: %prog [opts] [name=ip ...]")
    p.add_option('-d', dest='dnsServer', default=publicDNS, help='default DNS server')
    p.add_option('-6', dest='six', action='store_true', help='Use IPv6 server socket')
    opt,args = p.parse_args()
    opt.names = parseNames(args)
    opt.bindAddr = '' # any, ipv4 or ipv6
    opt.port = 53
    opt.dnsServerPort = 53
    opt.ttl = 60
    return opt

def main() :
    opt = getopts()
    server(opt)

if __name__ == '__main__' :
    main()
