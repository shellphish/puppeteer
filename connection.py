import socket
import select
import subprocess

import logging
l = logging.getLogger('puppeteer.connection')
#l.setLevel(logging.DEBUG)

from .errors import ConnectionFail

def rw_alias(f):
    '''
    Makes an alias for read/recv and write/send.
    '''
    print "CLASS:",f.im_class
    return f

class Connection(object):
    '''
    A connection handler for puppeteer. Basically a wrapper around sockets or
    files.

    Will handle all sorts of intelligent stuff like timeouts and crap.
    '''
    def __init__(self, host=None, port=None, exe=None):
        self.host = host
        self.port = port
        self.exe = exe

        self.s = None
        self.p = None
        self.connect()

    def connect(self):
        '''
        Connect!
        '''
        if self.host is not None and self.port is not None:
            self.s = socket.create_connection((self.host, self.port))
        elif self.exe is not None:
            self.p = subprocess.Popen(self.exe, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        else:
            raise Exception("How are we supposed to connect, man?")

    def send(self, msg):
        '''
        Send the message.
        '''
        l.debug("Sending: %r", msg)

        if self.s is not None:
            return self.s.sendall(msg)
        elif self.p is not None:
            return self.p.stdin.write(msg)

    def recv(self, n, timeout=None):
        '''
        Receive up to n bytes.
        '''
        #l.debug("recv(%d, timeout=%s)", n, timeout)
        slist = [ self.s if self.s is not None else self.p.stdout ]
        if timeout is not None:
            (rlist, _, _) = select.select(slist, [], [], timeout)
        else:
            (rlist, _, _) = select.select(slist, [], [])

        #print rlist, wlist, xlist
        if rlist == []:
            l.debug("RECV TIMEOUT")
            raise ConnectionFail("very timeout")
        readsock = rlist[0]
        if type(readsock) == socket.socket:
            r = readsock.recv(n)
        if type(readsock) == file:
            r = readsock.read(n)

        if len(r) == 0 and n != 0:
            raise ConnectionFail("Received nothing. Much sad.")

        #l.debug("Got: %r", r)
        return r

    def read(self, n=None, timeout=None):
        '''
        Read exactly n bytes, or all that's available if n is None.
        '''
        if n is None:
            self.read_all(timeout=timeout)

        result = ""
        while len(result) < n:
            tmp = self.recv(n - len(result), timeout=timeout)
            if tmp == "" and timeout is not None:
                break
            result += tmp

        return result

    # read until the given string
    def read_until(self, c, max_chars=None, timeout=None):
        '''
        Read until the given string.
        '''
        l.debug("Reading until: %r", c)

        buf = ""
        while max_chars is None or len(buf) < max_chars:
            #l.debug("... so far: %s", buf)
            if c in buf:
                #l.debug("... found!")
                break
            tmp = self.recv(1, timeout=timeout)
            if tmp == "":
                break
            buf += tmp
        l.debug("... read: %r", buf)
        return buf

    def read_all(self, timeout):
        '''
        Read as long as there is more stuff and the timeout is not expired.
        '''
        buff = ""

        while True:
            s = self.recv(8192, timeout=timeout)
            if len(s) == 0:
                break
            buff += s

        return buff

    def shutdown(self, what):
        if self.s is not None:
            self.s.shutdown(what)
        elif self.p is not None:
            if what == socket.SHUT_WR:
                self.p.stdin.close()
            if what == socket.SHUT_RD:
                self.p.stdout.close()
