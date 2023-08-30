import socket
import sys
import multiprocessing
import subprocess
import time

HOST_INTELLIGENCE = '127.0.0.1'
PORT_INTELLIGENCE = 514
CONTAINER_NAME = 'onos-1'

def send_information(data):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.sendto(data, (HOST_INTELLIGENCE, PORT_INTELLIGENCE))
            print("Log sent to Intelligence!")
        except ConnectionRefusedError:
            print("Connection refused. Make sure the receiver script is running.")

def receive_sdn_log():
    while True:
        # command = ["docker", "container", "logs", "--details", "--follow", CONTAINER_NAME] # production mode
        command = ["docker", "container", "logs", "--details", "--tail", "10", CONTAINER_NAME] # demonstration mode delete to production mode)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try:
            for line in process.stdout:
                line = line.strip()
                log_message = "[ONOS SDN LOG] : " + line
                print("Received log line:", log_message)
                send_information(log_message.encode()) # send to intelligence
        except KeyboardInterrupt:
            print("Keyboard interrupt received. Exiting...")
        
        process.communicate()
        time.sleep(10)  #for demonstration (delete to production mode)

def receive_host_log():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("172.17.0.1", 514))
    
    print("Syslog server started. Waiting for logs...")
    
    try:
        while True:
            data, address = server_socket.recvfrom(4096)
            send_information(data) # send to intelligence
            print(f"Received log from {address[0]}:\n{data.decode()}")
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Exiting...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    sdn_log_process = multiprocessing.Process(target=receive_sdn_log)
    host_log_process = multiprocessing.Process(target=receive_host_log)
    
    sdn_log_process.start()
    host_log_process.start()
    
    try:
        sdn_log_process.join()
        host_log_process.join()
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Exiting...")
