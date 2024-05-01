import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

def run_client():
    # create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "127.0.0.1"  
    server_port = 8000
    client.connect((server_ip, server_port))
    
    #AES Handshake

    #Receive Key
    key = client.recv(1024)

    #Send IV1
    cipher = AES.new(key, AES.MODE_CBC)
    client.send(cipher.iv)

    #Receive IV2
    iv2 = client.recv(1024)
    cipher2 =  AES.new(key, AES.MODE_CBC,iv2)

    while True:
        # Sending Request
        data = input("Enter Message: ")
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        client.send(ct_bytes)
        
        #Response Handling
        response  = client.recv(1024)
        pt = unpad(cipher2.decrypt(response), AES.block_size)
        print("Response: ", pt.decode('utf-8'))

run_client()