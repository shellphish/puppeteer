def memory_read(f):
    return memory_read_flags()(f)

def memory_read_flags(safe=True, max_size=None, min_addr=None, max_addr=None, priority=None):
    def decorator(f):
        flags = {
            'type':'memory_read',
            'safe':safe,
            'max_size':max_size,
            'min_addr':min_addr,
            'max_addr':max_addr,
            'priority':priority
        }
        setattr(f, 'puppeteer_flags', flags)
        return f
    return decorator

def memory_write(f):
    return memory_write_flags()(f)

def memory_write_flags(safe=True, max_size=None, min_addr=None, max_addr=None, priority=None):
    def decorator(f):
        flags = {
            'type':'memory_write',
            'priority':priority,
            'safe':safe,
            'max_size':max_size,
            'min_addr':min_addr,
            'max_addr':max_addr,
        }
        setattr(f, 'puppeteer_flags', flags)
        return f
    return decorator

def register_read(f):
    return register_read_flags()(f)

def register_read_flags(safe=True, priority=None):
    def decorator(f):
        flags = {
            'type':'register_read',
            'priority':priority,
            'safe':safe,
        }
        setattr(f, 'puppeteer_flags', flags)
        return f
    return decorator

def register_write(f):
    return register_write_flags()(f)

def register_write_flags(safe=True, priority=None):
    def decorator(f):
        flags = {
            'type':'register_write',
            'priority':priority,
            'safe':safe,
        }
        setattr(f, 'puppeteer_flags', flags)
        return f
    return decorator

def printf(f):
    return printf_flags()(f)

def printf_flags(safe=True, blind=False, max_fmt_size=None, max_output_size=None, bytes_to_fmt=None, priority=None):
    def decorator(f):
        flags = {
            'type':'printf',
            'priority':priority,
            'safe':safe,
            'blind':blind,
            'max_fmt_size':max_fmt_size,
            'max_output_size':max_output_size,
            'bytes_to_fmt':bytes_to_fmt
        }
        setattr(f, 'puppeteer_flags', flags)
        return f
    return decorator
