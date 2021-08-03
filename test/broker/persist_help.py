# This can be rewritten to easily support persistence plugins with all of
# the 15-persist-* tests.

def init(port):
    pass

def cleanup(port):
    return 0

def write_config(filename, port):
    with open(filename, 'w') as f:
        #f.write("plugin ..\n")
        pass
