import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad,pad

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


    # accept connection from client    
    client_socket, client_address = server.accept()

    print(f"Accepted connection from {client_address[0]}:{client_address[1]}")

    #AES Handshake

    #Set up the Keys
    key = get_random_bytes(16)    
    client_socket.send(key)

    #Receive IV1
    iv = client_socket.recv(1024)
    cipher = AES.new(key, AES.MODE_CBC,iv)

    #Send IV2
    cipher2 = AES.new(key,AES.MODE_CBC)
    client_socket.send(cipher2.iv)

    while True:
        #Request Handling
        ciphertext = client_socket.recv(1024)
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print("The message was: ", pt.decode('utf-8'))
        response = "Received".encode('utf-8')

        #Sending Response
        ct_bytes = cipher2.encrypt(pad(response, AES.block_size))
        client_socket.send(ct_bytes)

run_server()