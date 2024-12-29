#Network Sniffer- CodeAlpha CyberSecurity Internship

import pyshark
from pyshark.tshark.tshark import get_tshark_interfaces


 
def list_interfaces():
    print("Available Network Interfaces:")
    try:
        interfaces = get_tshark_interfaces()
        for i, interface in enumerate(interfaces):
            print(f"{i+1}. {interface}")
    except Exception as e:
        print(f"Error listing interfaces: {e}")



def get_valid_interface():
    while True:
        list_interfaces()
        interface = input("Enter the name of the network interface: ").strip()
        try:
            if interface in get_tshark_interfaces():
                return interface
            else:
                print("Invalid interface. Please try again.")
        except Exception as e:
            print(f"Error getting interfaces: {e}")



def analyze_packet(packet):
    try:
        print("\n Packet Details: ")
        if hasattr(packet, 'eth'):
            print("\nEthernet Frame:")
            print(f"Destination MAC: {packet.eth.dst}")
            print(f"Source MAC: {packet.eth.src}")
            print(f"Protocol: {packet.eth.type}")

        if hasattr(packet, 'ip'):
            print("\nIPv4 Packet:")
            print(f"Source IP: {packet.ip.src}")
            print(f"Destination IP: {packet.ip.dst}")
            print(f"Protocol: {packet.ip.proto}")

        if hasattr(packet, 'tcp'):
            print("\nTCP Segment:")
            print(f"Source Port: {packet.tcp.srcport}")
            print(f"Destination Port: {packet.tcp.dstport}")
            print(f"Sequence Number: {packet.tcp.seq}")
            print(f"Acknowledgment Number: {packet.tcp.ack}")
            print(f"Flags: {packet.tcp.flags}")
        elif hasattr(packet, 'udp'):
            print("\nUDP Segment:")
            print(f"Source Port: {packet.udp.srcport}")
            print(f"Destination Port: {packet.udp.dstport}")
        elif hasattr(packet, 'icmp'):
            print("\nICMP Packet:")
            print(f"Type: {packet.icmp.type}")
            print(f"Code: {packet.icmp.code}")
        elif hasattr(packet, 'ipv6'):
            print("\nIPv6 Packet:")
            print(f"Source IP: {packet.ipv6.src}")
            print(f"Destination IP: {packet.ipv6.dst}")
        elif hasattr(packet, 'arp'):
            print("\nARP Packet:")
            print(f"Source IP: {packet.arp.src_proto_ipv4}")
            print(f"Destination IP: {packet.arp.dst_proto_ipv4}")
        else:
            print("\nNo higher-layer protocol found in this packet.")

    except AttributeError as e:
        print(f"Error while reading packet attributes: {e}")



def main():
    interface = get_valid_interface()

    try:
        cap = pyshark.LiveCapture(interface=interface)
        print(f"Starting packet capture on interface '{interface}'...")

        for packet in cap.sniff_continuously(packet_count=10):
            analyze_packet(packet)

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    except Exception as e:
        print(f"Error during packet capture: {e}")
        

if __name__ == '__main__':
    main()
