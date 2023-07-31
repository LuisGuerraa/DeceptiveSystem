import socket
import threading

HOST_ATTACK_INFO_ADAPTER = '127.0.0.1'  # connect to Attack Info Adapter
PORT_ATTACK_INFO_ADAPTER = 5013 

HOST = '127.0.0.1' # receive from detection
PORT_LISTEN_SOPHISTICATED_DETECTION = 5002

attacker_ip=""
count=5

# ataques para playbook 4 (5 parametros)

type_of_attack4='sqli' 
attacker_ip4=''
attack_details4= 'cleSQL' 
threat_actor4= 'APT42'
cve4='CVE-2022-30927'


# ataques para playbook 3 (4 parametros)

type_of_attack3='sqli'
attacker_ip3=''
attack_details3= 'cleSQL' 
threat_actor3= 'APT42'
cve3=''

# ataques para playbook 2 (3 parametros)

type_of_attack2='ubuntu_exploitation'
attacker_ip2=''
attack_details2='kernel_exploit'
threat_actor2= ''
cve2=''

# ataques para playbook 1 (2 parametros)

type_of_attack='ubuntu_exploitation'
attacker_ip=''
attack_details=''
threat_actor= ''
cve=''


def start_socket_server(): # socket for receiving attack info from detection
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_LISTEN_SOPHISTICATED_DETECTION ))
        s.listen()
        print('Socket server listening on {}:{}'.format(HOST, PORT_LISTEN_SOPHISTICATED_DETECTION))
        while True:
          conn, addr = s.accept()
          print('Socket connection established from:', addr)
          threading.Thread(target=handle_socket, args=(conn,)).start()


def handle_socket(sock):
    while True:
        data = sock.recv(1024).decode()
        if not data:
            break
        params = data.split()
        
        global attacker_ip
        attacker_ip=params[0]
        
        global attacker_ip4
        attacker_ip4=params[0]
        global attacker_ip3
        attacker_ip3=params[0]
        global attacker_ip2
        attacker_ip2=params[0]
        global attacker_ip1
        attacker_ip1=params[0]
        
        global count
        count=count-1
        
        send_to_attack_info_adapter()
    sock.close()


def send_to_attack_info_adapter():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST_ATTACK_INFO_ADAPTER, PORT_ATTACK_INFO_ADAPTER))
        
        if count == 4:
           params = '{} {} {} {} {}'.format(type_of_attack4,attacker_ip4,attack_details4,threat_actor4,cve4)
        elif count == 3:
           params = '{} {} {} {} {}'.format(type_of_attack3,attacker_ip3,attack_details3,threat_actor3,cve3)
       
        s.sendall(params.encode())
        data = s.recv(1024)
        print('Attack Info adapter received the information.', repr(data.decode()))



if __name__ == '__main__': 
    start_socket_server()

