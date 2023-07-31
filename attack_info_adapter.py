import socket
import multiprocessing
import threading
import json


# send attack info to Deception Generator
HOST_DECEPTION_GENERATOR ='172.17.0.8' # Containernet IP address, change if necessary 
PORT_DECEPTION_GENERATOR = 5010        

# send attack info to Intelligence
HOST_INTELLIGENCE = '127.0.0.1'
PORT_INTELLIGENCE = 5012    

# receive attack info from auto_attack_analyst
HOST = '127.0.0.1' 
PORT_LISTEN_AUTO_ATTACK_ANALIST = 5013

type_of_attack=""
attacker_ip=""
attack_details=""
threat_actor= ""
cve=""

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def send_to_intelligence():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST_INTELLIGENCE, PORT_INTELLIGENCE))
        params = '{} {} {} {} {}'.format(type_of_attack,attacker_ip,attack_details,threat_actor,cve)
        s.sendall(params.encode())
        data = s.recv(1024)
        print('Intelligence received the information:', repr(data.decode()))

def send_to_deception_generator():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST_DECEPTION_GENERATOR, PORT_DECEPTION_GENERATOR))
        params = '{} {} {} {} {}'.format(type_of_attack,attacker_ip,attack_details,threat_actor,cve)
        s.sendall(params.encode())
        data = s.recv(1024)
        print(repr(data.decode()))


def send_information():
    # create separate processes for each socket connection
    p1 = multiprocessing.Process(target=send_to_intelligence)
    p2 = multiprocessing.Process(target=send_to_deception_generator)
    
    # start the processes in parallel
    p1.start()
    p2.start()
    
    # wait for the processes to finish
    p1.join()
    p2.join()


def start_socket_server(): # socket for receiving attack info from auto_attack_analyst
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_LISTEN_AUTO_ATTACK_ANALIST))
        s.listen()
        print('Socket server listening on {}:{}'.format(HOST, PORT_LISTEN_AUTO_ATTACK_ANALIST))
        while True:
            conn, addr = s.accept()
            print('Socket connection established from:', addr)
            threading.Thread(target=handle_socket, args=(conn,)).start() 


def adapt_information(data): 

    params = data.split()
    adapted_params = []

    json_attack_type = load_json(f'./attack_adapters/type_of_attack.json') # get system acknowledge type of attack
    adapted_params.append(json_attack_type.get(params[0]))

    adapted_params.append(params[1]) # attacker IP

    if len(params) > 2:
        json_attack_type = load_json(f'./attack_adapters/attack_details.json') # get system acknowledge type of attack
        adapted_params.append(json_attack_type.get(params[2]))

        if len(params) > 3:
            adapted_params.append(params[3]) # APT group
            if len(params) > 4:
                adapted_params.append(params[4]) # CVE

    return adapted_params

def handle_socket(sock):
    while True:
        data = sock.recv(1024).decode()
        if not data:
            break
        
        params = adapt_information(data)
        
        if len(params) < 2:
            sock.sendall(b'Error: At least type of attack [mandatory] and attacker IP [mandatory] are required')
            return

        global type_of_attack 
        type_of_attack = params[0] # mandatory
        global attacker_ip
        attacker_ip= params[1] # mandatory
        
        global threat_actor
        global attack_details
        global cve
        
        if len(params) > 2:    
            attack_details = params[2]
            threat_actor = ""
            cve = ""
        else:
            attack_details = ""
            threat_actor = ""
            cve = ""
            print ("No attack details were identified.")        
            
        if len(params) > 3:    
            threat_actor = params[3]
            cve = ""
        else:
            threat_actor = ""
            cve = ""
            print ("No threat actor was identified.")
        
        if len(params) > 4:
            cve = params[4]
        else:
            cve =""
            print ("No CVE was identified.")


        response_data = {'status': 'success', 'message': 'Attack information received successfully'}
        response = json.dumps(response_data)
        sock.sendall(response.encode())
        send_information() # send to intelligence and deception generator in parallel in two different processes
        

    sock.close()


def receive_attack_info ():
    start_socket_server() 

if __name__ == '__main__':
     receive_attack_info ()
    
    
    

    
   