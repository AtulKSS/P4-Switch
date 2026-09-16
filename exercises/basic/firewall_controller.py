#!/usr/bin/env python3

import sys
sys.path.append("../../utils")

from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib.bmv2 import Bmv2SwitchConnection
from scapy.all import sniff, IP, TCP 


packet_count = 0
attack_detected = False

THRESHOLD = 30

def connect():

    global sw
    global p4info_helper

    p4info_helper = P4InfoHelper("build/basic.p4.p4info.txtpb")

    sw = Bmv2SwitchConnection(
        name="s1",
        address="127.0.0.1:50051",
        device_id=0
    )

    sw.MasterArbitrationUpdate()

    print("Connected!")

def block_port(port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.tcp_port_block",
        match_fields={
            "hdr.tcp.dstPort": port
        },
        action_name="MyIngress.block_packet",
        action_params={}
    )

    sw.WriteTableEntry(table_entry)
    print(f"Blocked TCP port {port}")

def disconnect():

    sw.shutdown()

    print("Disconnected!")


def unblock_port(port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.tcp_port_block",
        match_fields={
            "hdr.tcp.dstPort": port
        },
        action_name="MyIngress.block_packet",
        action_params={}
    )

    sw.DeleteTableEntry(table_entry)
    print(f"Unblocked TCP port {port}")

if __name__ == "__main__":

    if len(sys.argv) != 3:

        print("Usage:")
        print("python3 firewall_controller.py block <port>")
        print("python3 firewall_controller.py unblock <port>")
        sys.exit(1)

    command = sys.argv[1]
    port = int(sys.argv[2])

    connect()

    if command == "block":
        block_port(port)

    elif command == "unblock":
        unblock_port(port)

    else:
        print("Unknown command")

    disconnect()

