import socket
import time
import sys 

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess

# Define the host and port of the receiver
receiver_host = '172.17.0.1'
receiver_port = 514

app = Flask(__name__)
CORS(app)

@app.route('/send_log', methods=['POST'])
def get_data():
    
    data=request.get_json()
    
    message = f"[mn.h4 - WebPage Log] WebPage loaded!! Attacker has seen the page with language: {data.get('language')} and message: {data.get('msg')}"
    
    send_message(message, receiver_host, receiver_port) # send to Asset Monitoring
    return "Roger that!"

def send_message(message, host, port): # send to Asset Monitoring
    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Send the message
            s.sendto(message.encode(), (host, port))

            print("Message sent successfully!")
        except ConnectionRefusedError:
            print("Connection refused by Asset Monitoring.")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9002)




    