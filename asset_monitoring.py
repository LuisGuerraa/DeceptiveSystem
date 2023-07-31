import socket
import sys
import multiprocessing

HOST_INTELLIGENCE = '127.0.0.1'
PORT_INTELLIGENCE  =  514

def send_information(data):
   
    p1 = multiprocessing.Process(target=forward_logs_to_intelligence, args=(data,))
    p1.start()
    p1.join()
    
def forward_logs_to_intelligence(data):
    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Send the message
            s.sendto(data, (HOST_INTELLIGENCE, PORT_INTELLIGENCE))

            print("Log sent to Intelligence!")
        except ConnectionRefusedError:
            print("Connection refused. Make sure the receiver script is running.") 


def receive_syslog():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("172.17.0.1", 514))

    print("Syslog server started. Waiting for logs...")
    
    try:
        while True:
            data, address = server_socket.recvfrom(4096)
            # parse logs
            send_information(data)# send to forward_logs_to_intelligence
            print(f"Received log from {address[0]}:\n{data.decode()}")
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Exiting...")
    finally:
        server_socket.close()
  
        
if __name__ == "__main__":
    receive_syslog()