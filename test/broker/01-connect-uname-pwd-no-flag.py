#!/usr/bin/env python3

# Test whether a connection is disconnected if it provides a password but the
# password flag is 0.

from mosq_test_helper import *


def do_test(start_broker, proto_ver):
    rc = 1
    keepalive = 10
    connect_packet = mosq_test.gen_connect("connect-uname-test", keepalive=keepalive, username="user", password="pw", proto_ver=proto_ver)
    b = list(struct.unpack("B"*len(connect_packet), connect_packet))
    b[9] = 66 # Remove password flag
    connect_packet = struct.pack("B"*len(b), *b)

    connack_packet = mosq_test.gen_connack(rc=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, b"", port=port)
        sock.close()
        rc = 0
    except mosq_test.TestError:
        pass
    finally:
        if start_broker:
            broker.terminate()
            broker.wait()
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                print("proto_ver=%d" % (proto_ver))
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
