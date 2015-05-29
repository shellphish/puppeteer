# puppeteer

puppeteer was an attempt to create an exploit framework, but it ended up being too overengineered and wasn't used too much. It's here for posterity.

# Old README:


It's time for a framework for super l337 exploit development!

We spent a lot of time, and a lot of implementation effort, making programs dance the way we want them. Why not automate some of that?

The general idea is that we will do the most while implementing the least. The design is as follows:

- the hacker creates a subclass of Manipulator, and implements the vulnerabilities they find (memory write, memory disclosure, printf vuln, whatever)
- that's it! Ideally, the system does the rest.

Manipulator is a class that, given some vulns, manipulates the program to do all sorts of zany stuff. We'll see how it works out in the end, but my current plan is to create another class, Puppetmaster, that'll handle creating multiple manipulators (for example, if memory disclosures end up crashing the program), or maybe Manipulator will take care of that itself. Anything could happen!

## Where to start?

To use this thing, you need to implement a subclass of Manipulator.

**\_\_init\_\_**

Your \_\_init\_\_ should make a connection to the program, or spawn it up, or whatever it is you're doing.

**The Vulnerabilities**

Vulns are implemented by creating a method with a decorator. There are default decorators for each action (the memory\_read below), and decorators that take options (the printf\_flags below).

	class YourFace(puppeteer.Manipulator):
		def __init__(self):
			# stuff

		@puppeteer.memory_read
		def some_leet_shit(self, addr, length):
			# l33t it up!

		@puppeteer.printf_flags(bytes_to_fmt=244):
		def lol(self, fmt):
			# ohnoes!

And with that, at some point in the future, you will be done. libc will be found and utilized to its full potential, and BOOM.

Ideally, we'd be able to automatically find the offset for the printf, too, so you can just use @printf instead of @printf\_flags!

## Features

- targeted read
- targeted write
- printf stuff

- PLT redirection
- callsite preparation

## TODO

- stack overwrite
- command injection
- blind command injection

- return addr overwrite
- library dumping
- stack frame dumping
- environment dumping
- information leak (ASLR)
- execute command
- read file(s)
- dump out process maps?

- maybe have some idalink support for determining more stuff automatically?
- rop stuff (at least find the cleanup gadgets automatically)
- identify the base address of libc, or just dump it
- implement the pwntools library searching stuff
