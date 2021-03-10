#!/usr/bin/env python3

# Test whether maximum packet size is honoured on a PUBLISH to a client
# MQTTv5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    keepalive = 10
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 35)
    connect_packet = mosq_test.gen_connect("12-max-publish", proto_ver=5, keepalive=keepalive, properties=props)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "12/max/publish/test/topic", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    publish1_packet = mosq_test.gen_publish(topic="12/max/publish/test/topic", qos=0, payload="12345678901234567890", proto_ver=5)
    publish2_packet = mosq_test.gen_publish(topic="12/max/publish/test/topic", qos=0, payload="67890", proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet)
        sock.send(publish1_packet)
        # We shouldn't receive the publish here because it is > MAXIMUM_PACKET_SIZE
        mosq_test.do_ping(sock, "pingresp1")
        mosq_test.do_send_receive(sock, publish2_packet, publish2_packet)
        mosq_test.do_ping(sock, "pingresp2")
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
