import scapy.all as scapy
import socket

try:
    ip=raw_input("Enter network IP x.x.x.x/CIDR : ")
    arp_request=scapy.ARP(pdst=ip)
    ether_frame=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet=ether_frame/arp_request
    answered=scapy.srp(packet,timeout=1,verbose=False)[0]
except (socket.gaierror,EOFError,NameError,KeyboardInterrupt,ValueError) as e:
    print("[INFO] Exiting program...")
    exit()
except socket.error:
    print("[ERROR] Run as Root User...")
    exit()

print("IP Address\t\tMAC Address")
for element in answered:
    print(element[1].psrc+"\t\t"+element[1].hwsrc)
