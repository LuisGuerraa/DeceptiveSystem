import socket
import subprocess
from multiprocessing import Process, Value
import sys

HOST_ATTACK_INFO_ADAPTER ='172.17.0.8' #'127.0.0.1'  # listens for attack_info_adapter
PORT_ATTACK_INFO_ADAPTER = 5010

HOST_INTELLIGENCE_API = '172.17.0.8' #'127.0.0.1'   # listens for intelligence_api
PORT_INTELLIGENCE_API = 5014

PORT_INTELLIGENCE_API_POSTMORTEM = 5045

MAX_DECEPTION_GRIDS=2

deception_grids_counter = Value('i', 0)

def deception_build(full_data, type_of_attack,attacker_ip, attack_details, threat_actor,cve):
    # choose a plan for this data
    print("Full data : ", full_data)
    print("Type of attack : ", type_of_attack)
    print("Attacker IP Address : ", attacker_ip)
    print("Details of the attack : ", attack_details)
    print("Threat actor : ", threat_actor)
    print("CVE : ", cve)
    
    # static deception planner
    # the goal is to launch the other script and terminate this to enable to run again and receive other plans

    
    # "None" verification is when attack comes from attack_info_adapter and bool for research deployment through intelligence api deployment

   # if (type_of_attack is not None or bool(type_of_attack)) and (attacker_ip is not None or bool(attacker_ip)) and (not attack_details or not bool(attack_details)) and (not threat_actor or not bool(threat_actor)):
   # 	subprocess.Popen(['python3', 'playbook1.py',type_of_attack,attacker_ip])
   #     sys.exit()
    
   # else :
   #     if (type_of_attack is not None or bool(type_of_attack)) and (attacker_ip is not None or bool(attacker_ip)) and (attack_details is not None or bool(attack_details)) and (not threat_actor or not bool(threat_actor)):
   # 	    subprocess.Popen(['python3', 'playbook2.py',type_of_attack,attacker_ip, attack_details])
   # 	    sys.exit()
   #     else:
   #         if (type_of_attack is not None or bool(type_of_attack)) and (attacker_ip is not None or bool(attacker_ip)) and (attack_details is not None or bool(attack_details)) and (threat_actor is not None or bool(threat_actor)):
   #             subprocess.Popen(['python3', 'playbook3.py',type_of_attack,attacker_ip, attack_details, threat_actor])
   #             sys.exit()
    
    subprocess.Popen(['python3', 'static_deception_planner.py',type_of_attack,attacker_ip, attack_details, threat_actor, cve])


def handle_connection_from_attack_info_adapter(conn, addr,deception_grids_counter):

    with deception_grids_counter.get_lock():
       deception_grids_counter.value += 1
        
    print("Connected by {}".format(addr))
    data = conn.recv(1024).decode('utf-8')
    params = data.split()

    if len(params) < 2:
        conn.sendall(b'Error: At least a plan, attack_type and IP are required')
    else:        
        attack_type = params[0]
        ip = params[1]
         
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

        if deception_grids_counter.value  <= MAX_DECEPTION_GRIDS:        
            conn.sendall(b'Deception Generator received the deployment command') 
            
            deception_build(data,attack_type,ip,attack_details,threat_actor,cve)  # Research deployment -> Deploy grid as landmine in infrastructure following provided data
        else:
            print('Maximum number of deployed deception grids was hit.')
            conn.sendall(b'Maximum number of deployed deception grids was hit.') 
    conn.close()

def handle_connection_from_intelligence(conn, addr,deception_grids_counter):
    
    with deception_grids_counter.get_lock():
       deception_grids_counter.value += 1
        
    print("Connected by {}".format(addr))
    data = conn.recv(1024).decode('utf-8')
    params = data.split()

    if len(params) < 2:
        conn.sendall(b'Error: At least a plan, attack_type and IP are required')
    else:        
        attack_type = params[0]
        ip = params[1]
         
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

        if deception_grids_counter.value  <= MAX_DECEPTION_GRIDS:        
            conn.sendall(b'Deception Generator received the deployment command') 
            deception_build(data,attack_type,ip,attack_details,threat_actor,cve)  # Research deployment -> Deploy grid as landmine in infrastructure following provided data
        else:
            print('Maximum number of deployed deception grids was hit.')
            conn.sendall(b'Maximum number of deployed deception grids was hit.') 

    conn.close()

def export_container_filesystem(container_id_or_name, output_file):
    with open(output_file, 'wb') as file:
        subprocess.run(['docker', 'export', container_id_or_name], stdout=file)

def stop_container(container_id_or_name):
    subprocess.run(['docker', 'stop', container_id_or_name])

def remove_container(container_id_or_name):
    subprocess.run(['docker', 'rm', container_id_or_name])

def handle_connection_from_intelligence_perform_postmortem(conn, addr):

    print("Connected by {} to perform postmortem host saving.".format(addr))
    data = conn.recv(1024).decode('utf-8')
    params = data.split()
   
    container_id_or_name = params[0]
    output_file = params[1]
    print ("Preserving host state and storing of post-mortem forensics...")
       
    print ("Exporting container file to {}...", output_file)
    export_container_filesystem(container_id_or_name, output_file)
        
    print ("Stopping and removing container...")
       
    stop_container(container_id_or_name)
    remove_container(container_id_or_name)
    
    conn.close()

def accept_connections(args):
    s, deception_grids_counter = args
    while True:
        conn, addr = s.accept()
        if s.getsockname()[1] == PORT_ATTACK_INFO_ADAPTER:
            p = Process(target=handle_connection_from_attack_info_adapter, args=(conn, addr, deception_grids_counter))
        elif s.getsockname()[1] == PORT_INTELLIGENCE_API:
            p = Process(target=handle_connection_from_intelligence, args=(conn, addr, deception_grids_counter))
        elif s.getsockname()[1] == PORT_INTELLIGENCE_API_POSTMORTEM:
            p = Process(target=handle_connection_from_intelligence_perform_postmortem, args=(conn, addr))
        p.start()


s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s1.bind((HOST_ATTACK_INFO_ADAPTER, PORT_ATTACK_INFO_ADAPTER))
s2.bind((HOST_INTELLIGENCE_API, PORT_INTELLIGENCE_API))
s3.bind((HOST_INTELLIGENCE_API, PORT_INTELLIGENCE_API_POSTMORTEM))

s1.listen()
s2.listen()
s3.listen()

print(f"Listening on {HOST_ATTACK_INFO_ADAPTER}:{PORT_ATTACK_INFO_ADAPTER}")
print(f"Listening on {HOST_INTELLIGENCE_API}:{PORT_INTELLIGENCE_API}")
print(f"Listening on {HOST_INTELLIGENCE_API}:{PORT_INTELLIGENCE_API_POSTMORTEM}")

try:
    # start the processes to accept incoming connections on both sockets
    p1 = Process(target=accept_connections, args=((s1,deception_grids_counter),))
    p2 = Process(target=accept_connections, args=((s2,deception_grids_counter),))
    p3 = Process(target=accept_connections, args=((s3,deception_grids_counter),))

    p1.start()
    p2.start()
    p3.start()

    # wait for the processes to finish
    p1.join()
    p2.join()
    p3.join()

except KeyboardInterrupt:
    print("Exiting...")
    s1.close()
    s2.close()
    s3.close()

# close the sockets
#s1.close()
#s2.close()
