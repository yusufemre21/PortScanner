from scapy.all import ARP, Ether, srp
import socket

def scan_local_network(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append(received.psrc)
    return devices

def scan_ports(devices, ports):
    open_ports = []

    for device in devices:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((device, port))
            if result == 0:
                try:
                    host_info = socket.gethostbyaddr(device)
                    hostname = host_info[0] if host_info else "Unknown"
                except socket.herror:
                    hostname = "Unknown"
                open_ports.append((device, port, hostname))

            sock.close()

    return open_ports

target_ip = "192.168.1.0/24"
connected_devices = scan_local_network(target_ip)

devices_to_scan = connected_devices
ports_to_scan = [80, 443, 22, 25, 21, 110, 143, 53, 3389, 3306, 8080]

open_ports = scan_ports(devices_to_scan, ports_to_scan)
print("Open Ports:")
for item in open_ports:
    device, port, hostname = item
    print(f"IP: {device}, Port: {port}, Device Name: {hostname}")
input("Press the 'Enter' key to Close the Port Scanner.")
