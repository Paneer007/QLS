import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

def run_server():
    # create a socket object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "127.0.0.1"
    port = 8000

    # bind the socket to a specific address and port
    server.bind((server_ip, port))
    # listen for incoming connections
    server.listen(0)
    
    print(f"Listening on {server_ip}:{port}")

    #Set up the Keys
    key = get_random_bytes(16)    
    # accept connection from client    
    client_socket, client_address = server.accept()

    print(f"Accepted connection from {client_address[0]}:{client_address[1]}")
    
    client_socket.send(key)
    iv = client_socket.recv(1024)
    cipher = AES.new(key, AES.MODE_CBC,iv)

    while True:
        ciphertext = client_socket.recv(1024)
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print("The message was: ", pt.decode('utf-8'))

run_server()