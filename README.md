
# Network Sniffer - CodeAlpha Cybersecurity Internship

## 🌟 Overview
This project is a **Network Sniffer** developed as part of  the **CodeAlpha Cybersecurity Internship**. It uses Python and the `pyshark` library to capture and analyze network packets in real-time. The tool provides detailed information about Ethernet, IP, TCP, UDP, ICMP, IPv6, and ARP packets.

## 💡 Features
- **Interface Listing**: Lists all available network interfaces for selection.
- **Real-Time Packet Capture**: Captures live network traffic.
- **Detailed Packet Analysis**:
  - Ethernet Frame details (MAC addresses, Protocol).
  - IPv4 and IPv6 Packet details (Source/Destination IP, Protocol).
  - TCP and UDP Segment details (Ports, Flags, Sequence Number).
  - ICMP Packet details (Type, Code).
  - ARP Packet details.

## 📋 Requirements
1. **Python 3.x** installed on your system.
2. **Wireshark/Tshark** (required by `pyshark`):
   - Install from [Wireshark's official site](https://www.wireshark.org/download.html).
3. **Python Libraries**:
   - Install `pyshark` using:
     ```bash
     pip install pyshark
     ```
