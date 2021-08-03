#!/usr/bin/env python3

# Connect a client, start a QoS 2 flow, disconnect, restore, carry on with the
# QoS 2 flow. Is it received?

from mosq_test_helper import *
import persist_help

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1

persist_help.init(port)

keepalive = 10
client_id = "persist-client-msg-in-v3-1-1"
proto_ver = 4

helper_id = "persist-client-msg-in-v3-1-1-helper"
topic = "client-msg-in/2"
qos = 2

connect_packet = mosq_test.gen_connect(client_id, keepalive=keepalive, proto_ver=proto_ver, clean_session=False)
connack_packet1 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
connack_packet2 = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)
mid = 1
publish_packet = mosq_test.gen_publish(topic=topic, qos=qos, payload="message", mid=mid, proto_ver=proto_ver)
pubrec_packet = mosq_test.gen_pubrec(mid=mid, proto_ver=proto_ver)
pubrel_packet = mosq_test.gen_pubrel(mid=mid, proto_ver=proto_ver)
pubcomp_packet = mosq_test.gen_pubcomp(mid=mid, proto_ver=proto_ver)

connect_packet_helper = mosq_test.gen_connect(helper_id, keepalive=keepalive, proto_ver=proto_ver, clean_session=True)
subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos=qos, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid=mid, qos=qos, proto_ver=proto_ver)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

con = None
try:
    # Connect client, start flow, disconnect
    sock = mosq_test.do_client_connect(connect_packet, connack_packet1, timeout=5, port=port)
    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec send")
    sock.close()

    # Kill broker
    broker.terminate()
    broker.wait()

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect helper and subscribe
    helper = mosq_test.do_client_connect(connect_packet_helper, connack_packet1, timeout=5, port=port)
    mosq_test.do_send_receive(helper, subscribe_packet, suback_packet, "suback helper")

    # Complete the flow
    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=5, port=port)
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubrel send")

    mosq_test.do_receive_send(helper, publish_packet, pubrec_packet, "pubrec receive")
    mosq_test.do_receive_send(helper, pubrel_packet, pubcomp_packet, "pubcomp receive")

    rc = 0
finally:
    if broker is not None:
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
    os.remove(conf_file)
    rc += persist_help.cleanup(port)

    if rc:
        print(stde.decode('utf-8'))


exit(rc)
