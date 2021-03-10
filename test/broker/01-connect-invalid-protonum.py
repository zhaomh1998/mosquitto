#!/usr/bin/env python3

# Test whether a CONNECT with an invalid protocol number results in the correct CONNACK packet.

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    keepalive = 10
    connect_packet = mosq_test.gen_connect("01-connect-invalid-protonum", keepalive=keepalive, proto_ver=0)
    connack_packet = mosq_test.gen_connack(rc=1)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
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
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
