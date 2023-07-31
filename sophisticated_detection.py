import socket
import os
import struct
import sys

HOST_AUTO_ATTACK_ANALYST = '127.0.0.1'  # connect to Intelligence
PORT_AUTO_ATTACK_ANALYST = 5002

# Create a raw socket and bind it to listen for ICMP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.bind(('', 0))

# Function to receive and parse ICMP packets
def receive_ping():
    packet = sock.recvfrom(65535)[0]
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    icmp_packet = packet[iph_length:]
    icmp_type, icmp_code, icmp_checksum = struct.unpack('!BBH', icmp_packet[:4])


     # Process ICMP echo requests (type 8)
    if icmp_type == 8 and icmp_code == 0:
       s_addr = socket.inet_ntoa(iph[8])
       print(f"Received ICMP ping from: {s_addr}")
       send_to_auto_attack_analyst(s_addr)


def send_to_auto_attack_analyst(attacker_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST_AUTO_ATTACK_ANALYST, PORT_AUTO_ATTACK_ANALYST))
        params = '{}'.format(attacker_ip)
        s.sendall(params.encode())
        data = s.recv(1024)
        print('Auto attack analyst received the information.', repr(data.decode()))   


try:
    while True:

        receive_ping()
        break
    
except KeyboardInterrupt:

    print("Exiting...")
    sys.exit()           

            

            

            

            

            