import socket
import re

import nose

import puppeteer

def test_connection():
    from puppeteer import Connection
    
    # recv_until a regex is matched
    conn = Connection(host='ifconfig.io', port=80)
    conn.connect()
    # Read until we get the IP address
    conn.send("""GET / HTTP/1.1\r
User-Agent: curl\r
Host: ifconfig.io\r
\r
""")
    regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\n"
    data = conn.read_until(regex=regex)
    nose.tools.assert_true(re.search(regex, data))

if __name__ == "__main__":
    # Run all tests
    g = globals().copy()
    for func_name, func in g.iteritems():
        if func_name.startswith('test_'):
            func()

