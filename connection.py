import socket
import subprocess

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
        if self.host is not None and self.port is not None:
            self.s = socket.create_connection((self.host, self.port))
        elif self.exe is not None:
            self.p = subprocess.Popen(self.exe, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        else:
            raise Exception("How are we supposed to connect, man?")

    def send(self, msg):
        if self.s is not None:
            return self.s.sendall(msg)
        elif self.p is not None:
            return self.p.stdin.write(msg)
    def write(self, msg): return self.send(msg)

    def recv(self, n):
        if self.s is not None:
            return self.s.recv(n)
        elif self.p is not None:
            return self.p.stdout.read(n)
    def read(self, n): return self.recv(n)

    def shutdown(self, what):
        if self.s is not None:
            self.s.shutdown(what)
        elif self.p is not None:
            if what == socket.SHUT_WR:
                self.p.stdin.close()
            if what == socket.SHUT_RD:
                self.p.stdout.close()
