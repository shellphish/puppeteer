#!/usr/bin/env python

import logging
l = logging.getLogger("puppeteer.architectures")

# pylint: disable=no-init

class x86:
	bits = 32
	bytes = 4
	sp_name = 'esp'
	ip_name = 'eip'
	bp_name = 'ebp'
	endness = '<'
	struct_char = "I"
	struct_fmt = '<I'
	python_fmt = "%08x"
	page_size = 0x1000
	gas="x86-as"
	objcopy="x86-objcopy"

class amd64:
	bits = 64
	bytes = 8
	sp_name = 'rsp'
	ip_name = 'rip'
	bp_name = 'rbp'
	endness = '<'
	struct_char = "Q"
	struct_fmt = '<Q'
	python_fmt = "%16x"
	page_size = 0x1000
	gas="x86_64-as"
	objcopy="x86_64-objcopy"

class arm:
	bits = 32
	bytes = 4
	sp_name = 'r13'
	ip_name = 'r15'
	bp_name = 'something'
	endness = '<'
	struct_char = "I"
	struct_fmt = '<I'
	python_fmt = "%08x"
	page_size = 0x1000
	gas="arm-as"
	objcopy="arm-objcopy"

class ppc:
	bits = 32
	bytes = 4
	sp_name = 'something'
	ip_name = 'something'
	bp_name = 'something'
	endness = '>'
	struct_char = "I"
	struct_fmt = '>I'
	python_fmt = "%08x"
	page_size = 0x1000
	gas="ppc-as"
	objcopy="ppc-objcopy"

class mips:
	bits = 32
	bytes = 4
	sp_name = 'something'
	ip_name = 'something'
	bp_name = 'something'
	endness = '>'
	struct_char = "I"
	struct_fmt = '>I'
	python_fmt = "%08x"
	page_size = 0x1000
	gas="ppc-as"
	objcopy="ppc-objcopy"
