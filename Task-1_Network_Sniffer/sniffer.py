import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = f"PROTO-{packet[IP].proto}"

    print(f"[{protocol}] {src_ip} -> {dst_ip}")

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
            if payload:
                print(f"    Payload: {payload[:60]}")
        except Exception:
            print(f"    Raw (Hex): {packet[Raw].load[:20].hex()}")

def main():
    print("[*] Starting network sniffer... Press Ctrl+C to stop.")

    try:
        sniff(filter="ip", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Error: Root/Administrator privileges required to capture packets.")
        sys.exit(1)

if __name__ == "__main__":
    main()