import logging
l = logging.getLogger("puppeteer.utils")

from .errors import NotLeetEnough

def unleet(msg):
	l.warning(msg)
	raise NotLeetEnough(msg)
