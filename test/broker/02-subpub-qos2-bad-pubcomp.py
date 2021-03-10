#!/usr/bin/env python3

# Test what the broker does if receiving a PUBCOMP in response to a QoS 2 PUBLISH.

from mosq_test_helper import *

def helper(port, proto_ver):
    connect_packet = mosq_test.gen_connect("02-subpub-qos2-bad-pubcomp-helper", keepalive=60, proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    publish1s_packet = mosq_test.gen_publish("02/subpub/qos2/bad/pubcomp", qos=2, mid=mid, payload="message", proto_ver=proto_ver)
    pubrec1s_packet = mosq_test.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel1s_packet = mosq_test.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp1s_packet = mosq_test.gen_pubcomp(mid, proto_ver=proto_ver)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, publish1s_packet, pubrec1s_packet, "pubrec 1s")
    mosq_test.do_send_receive(sock, pubrel1s_packet, pubcomp1s_packet, "pubcomp 1s")
    sock.close()


def do_test(start_broker, proto_ver):
    rc = 1
    keepalive = 60

    connect_packet = mosq_test.gen_connect("02-subpub-qos2-bad-pubcomp", keepalive=keepalive, proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "02/subpub/qos2/bad/pubcomp", 2, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 1
    publish1r_packet = mosq_test.gen_publish("02/subpub/qos2/bad/pubcomp", qos=2, mid=mid, payload="message", proto_ver=proto_ver)
    pubcomp1r_packet = mosq_test.gen_pubcomp(mid, proto_ver=proto_ver)

    pingreq_packet = mosq_test.gen_pingreq()
    pingresp_packet = mosq_test.gen_pingresp()

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port, proto_ver)

        mosq_test.expect_packet(sock, "publish 1r", publish1r_packet)
        sock.send(pubcomp1r_packet)
        sock.send(pingreq_packet)
        p = sock.recv(len(pingresp_packet))
        if len(p) == 0:
            rc = 0

        sock.close()
    except socket.error as e:
        if e.errno == errno.ECONNRESET:
            # Connection has been closed by peer, this is the expected behaviour
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
