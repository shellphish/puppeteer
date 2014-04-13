import logging
l = logging.getLogger("puppeteer.utils")

def read_until(s, what, timeout=None):
    l.debug("Reading until %s", what.encode('hex'))

    content = ""
    while not content.endswith(what):
        l.debug("So far: %s (size %d)", content, len(content))
        try:
            content += s.recv(1)
        except Exception:
            break
    return content
