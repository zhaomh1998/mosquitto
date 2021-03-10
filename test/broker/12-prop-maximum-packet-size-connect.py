#!/usr/bin/env python3

# Test whether setting maximum packet size to smaller than a CONNACK packet
# results in the CONNECT being rejected.
# MQTTv5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    keepalive = 5
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 2)
    connect_packet = mosq_test.gen_connect("12-max-packet-connect", proto_ver=5, keepalive=keepalive, properties=props)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, b"", port=port)
        # Exception occurs if connack packet returned
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
