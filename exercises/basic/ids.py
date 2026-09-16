from scapy.all import sniff, IP, TCP
from firewall_controller import connect, disconnect, block_port

packet_count = 0
attack_detected = False

THRESHOLD = 20

def detect(packet):

    global packet_count
    global attack_detected

    if attack_detected:
        return

    packet_count += 1

    if IP in packet and TCP in packet:

    	print(
           f"[{packet_count}] "
           f"SRC={packet[IP].src}  "
           f"DST={packet[IP].dst}  "
           f"PROTO=TCP  "
           f"DST_PORT={packet[TCP].dport}"
    )

    if packet_count >= 20:

        attack_detected = True

        print("\n===================================")
        print("⚠ ATTACK DETECTED!")
        print("Threshold reached: 20 packets")
        print("Blocking TCP Port 5001...")
        print("===================================\n")

        block_port(5001)

        print("✓ Prevention Action Successful")


if __name__ == "__main__":

    connect()

    print("IDS Started...")
    print("Waiting for TCP packets...\n")

    sniff(
        filter="tcp",
        prn=detect,
        store=False
    )

    disconnect()
