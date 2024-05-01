import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def run_client():
    # create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "127.0.0.1"  
    server_port = 8000 
    client.connect((server_ip, server_port))
    
    key = client.recv(1024)
    cipher = AES.new(key, AES.MODE_CBC)
    client.send(cipher.iv)

    while True:
        # input message and send it to the server
        data = input("Enter Message: ")
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        client.send(ct_bytes)

run_client()