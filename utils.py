import logging
l = logging.getLogger("puppeteer.utils")

from .errors import NotLeetEnough

def unleet(msg, level=logging.WARNING):
	l.log(level, msg)
	raise NotLeetEnough(msg)
