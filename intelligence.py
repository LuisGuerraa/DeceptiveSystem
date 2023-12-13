from flask import Flask, request, jsonify
import socket
import threading
import requests
import json
import datetime
import subprocess
import multiprocessing


app = Flask(__name__)

type_of_attack = ""
attacker_ip = ""
attack_details = ""
threat_actor = ""
cve = ""

recorded_attacks = []
recorded_deployments =[]

SDN_logs = []
container_Logs = []

HOST_DECEPTION_GENERATOR = '172.17.0.8' # 127.0.0.1  # connect to Deception Generator
PORT_DECEPTION_GENERATOR = 5014
PORT_DECEPTION_GENERATOR_POST_MORTEM = 5045

HOST = '127.0.0.1'

PORT_LISTEN_ATTACK_INFO_ADAPTER = 5012 

PORT_LISTEN_LOGS = 514

HOST_SIEM = '10.0.2.14'
SIEM_PORT = 514

@app.route('/api/attacks', methods=['GET'])
def get_recorded_attacks(): 
    recorded_attacks_parsed = []
    for attack in recorded_attacks:
        attack_dict={'type_of_attack': attack['type_of_attack'], 'attacker_ip': attack['attacker_ip'], 'attack_details':  attack['attack_details'],'threat_actor': attack['threat_actor'],'cve': attack['cve'],'date/time': attack['date/time']}
        recorded_attacks_parsed.append(attack_dict)
    return jsonify(recorded_attacks_parsed)

@app.route('/api/deployments', methods=['GET'])
def get_recorded_deployments(): 
    return jsonify(recorded_deployments)

@app.route('/api/topology/<string:controller_ip>', methods=['GET'])
def get_deception_grid_topology(controller_ip):
    sdn_controller_ip = controller_ip
    controller_rest_url = "http://{}:8181/onos/v1/".format(sdn_controller_ip) 
    headers = {'Accept' : 'application/json'}

    response = requests.get(controller_rest_url + "devices", headers=headers, auth=('onos','rocks'))
    devices_data = response.json()    

    response2 = requests.get(controller_rest_url + "hosts", headers=headers, auth=('onos','rocks'))
    hosts_data = response2.json()    

    merged_data = {}
    merged_data["NETWORK_DEVICES"] = devices_data
    merged_data["HOSTS"] = hosts_data

    return jsonify(merged_data)

@app.route('/api/hosts/<string:controller_ip>', methods=['POST'])
def deploy_host(controller_ip):
    sdn_controller_ip = controller_ip
    controller_rest_url = "http://{}:8181/onos/v1/".format(sdn_controller_ip) 
    data = request.get_json()
    headers = {'Accept' : 'application/json'}
    data_to_send = { 'ipAddresses' : [data.get('host_ip')], 'mac': data.get('host_mac'), 'vlan' : data.get('vlan'), 'locations' : [{'elementId' : data.get('switch_name'), 'port' : data.get('port')}]}
    response1 = requests.post(controller_rest_url+"hosts", headers=headers, data=json.dumps(data_to_send), auth=('onos','rocks'))
    
    return response1.text
    
@app.route('/api/hosts/<string:controller_ip>', methods=['DELETE'])
def remove_host(controller_ip):
    sdn_controller_ip = controller_ip
    controller_rest_url = "http://{}:8181/onos/v1/".format(sdn_controller_ip) 
    data = request.get_json()
    headers = {'Accept' : 'application/json'}
    container_id_or_name = data.get('container_id_or_name')
    
    response1 = requests.delete(controller_rest_url+"hosts/{}/{}".format(data.get('host_mac'),data.get('vlan')), headers=headers, auth=('onos','rocks'))

    perform_postmortem = request.args.get('postmortem', '').lower() == 'true'

    if perform_postmortem:
        
        output_file = data.get('output_file')
        threading.Thread(target=post_mortem_command, args=(container_id_or_name,output_file,)).start()
    
    else:
        subprocess.run(['docker', 'stop', container_id_or_name])
        subprocess.run(['docker', 'rm', container_id_or_name])    
    return response1.text

def post_mortem_command(container_id_or_name,output_file):
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s3:
            s3.connect((HOST_DECEPTION_GENERATOR, PORT_DECEPTION_GENERATOR_POST_MORTEM))
            params = '{} {}'.format(container_id_or_name,output_file)
            s3.sendall(params.encode())
            data = s3.recv(1024)
            print(repr(data.decode())) # print response from deception generator


@app.route('/api/topology', methods=['POST']) 
def deploy_deception_grid():
    data = request.get_json()
 
    attack_type = data.get('attack_type')
    ip = data.get('IP')
    attack_details = data.get('attack_details')
    threat_actor = data.get('threat_actor')
    cve = data.get('cve')
 
    date_to_record = datetime.datetime.now() # save current timestamp/date
    data['date/time'] = date_to_record
    
    global recorded_deployments
    recorded_deployments.append(data)
    threading.Thread(target=deploy_grid, args=(attack_type,ip,attack_details,threat_actor,cve,)).start()
    print('Deployment command and information received : ', data)

    # Return a JSON response for HTTP request client
    response_data = {'status': 'success', 'message': 'Deployment command sent successfully for attack type = {}, ip = {}, attack details = {} and threat actor = {}'.format(attack_type,ip,attack_details,threat_actor)}
    return jsonify(response_data)


def deploy_grid(attack_type,ip,attack_details,threat_actor,cve):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
        s2.connect((HOST_DECEPTION_GENERATOR, PORT_DECEPTION_GENERATOR))
        params = '{} {} {} {} {}'.format(attack_type,ip,attack_details,threat_actor,cve)
        s2.sendall(params.encode())
        data = s2.recv(1024)
        print(repr(data.decode())) # print response from deception generator


def handle_socket(sock):
    while True:
        data = sock.recv(1024).decode()
        if not data:
            break
        
        params = data.split()
        if len(params) < 2:
            sock.sendall(b'Error: At least type of attack [mandatory] and attacker IP [mandatory] are required')
            
        global type_of_attack 
        type_of_attack = params[0]
        global attacker_ip
        attacker_ip= params[1]
        
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
            
        print('Attack triggered and information received : ', data)
        date_to_record = datetime.datetime.now() # save current timestamp/date
        recorded_attack = {'type_of_attack': type_of_attack, 'attacker_ip': attacker_ip, 'attack_details': attack_details,'threat_actor': threat_actor, 'cve': cve, 'date/time': date_to_record}
        global recorded_attacks  
        recorded_attacks.append(recorded_attack)
        response_data = {'status': 'success', 'message': 'Attack information received successfully'}
        response = json.dumps(response_data)
        sock.sendall(response.encode())
        
        #TODO [OPTIONAL] SEND TO SIEM ATTACK INFO

    sock.close()

def attack_info_receptor(): # socket for receiving attack info from attack_info_adapter
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_LISTEN_ATTACK_INFO_ADAPTER))
        s.listen()
        print('Socket server listening on {}:{}'.format(HOST, PORT_LISTEN_ATTACK_INFO_ADAPTER))
        while True:
            conn, addr = s.accept()
            print('Socket connection established from:', addr)
            threading.Thread(target=handle_socket, args=(conn,)).start() 


def send_information_siem(data):
   
    p1 = multiprocessing.Process(target=send_siem, args=(data,))
    p1.start()
    p1.join()
    
def send_siem(data):
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            
            s.sendto(data, (HOST_SIEM, SIEM_PORT))

            #print("Log sent to SIEM!")
        except ConnectionRefusedError:
            print("Connection refused. Make sure the receiver script is running.")


def logs_receptor():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, PORT_LISTEN_LOGS))

    print("Syslog server started. Waiting for logs...")
    
    try:
        while True:
            data, address = server_socket.recvfrom(4096)
            send_information_siem(data)
            #print(f"Received log from {address[0]}:\n{data.decode()}")
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Exiting...")
    finally:
        server_socket.close()


def start_flask_server():
    app.run()

if __name__ == '__main__':
    threading.Thread(target=attack_info_receptor).start()
    threading.Thread(target=start_flask_server).start()
    threading.Thread(target=logs_receptor).start()