import socket
import time

def send_message(message, host, port):
    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Send the message
            s.sendto(message.encode(), (host, port))

            print("Message sent successfully!")
        except ConnectionRefusedError:
            print("Connection refused. Make sure the receiver script is running.")


# Define the host and port of the receiver
receiver_host = '172.17.0.1'
receiver_port = 514

# Define the message to send
message = "[mn.h1 - mySQL Log] hello world"

while True:
    send_message(message, receiver_host, receiver_port)
    time.sleep(5)