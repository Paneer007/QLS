from qiskit import QuantumCircuit, execute, Aer
from numpy.random import randint
import numpy as np
import socket
import pickle
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

NUM_QUBITS = 96


def select_random_indices(arr):
    num_indices = len(arr) // 4
    random_indices = random.sample(range(len(arr)), num_indices)
    result = {index: arr[index] for index in random_indices}
    return result

def generate_bits(n: int) -> np.ndarray:
    return randint(2, size=n)

def measure_message(message: list, basis: np.ndarray) -> list:
    backend = Aer.get_backend("qasm_simulator")
    measurements = []
    for q in range(NUM_QUBITS):
        if basis[q] == 1:  # Measuring in X-basis
            message[q].h(0)
        message[q].measure(0, 0)
        result = execute(message[q], backend, shots=1, memory=True).result()
        measurements.append(int(result.get_memory()[0]))
    return measurements

def remove_garbage(a_basis: np.ndarray, b_basis: np.ndarray, bits: np.ndarray) -> list:
    return [bits[q] for q in range(NUM_QUBITS) if a_basis[q] == b_basis[q]]  # Removes bits that do not match

def recv_stream(conn):
    received_data = b""
    while True:
        str = conn.recv()
        if str[-4:] == b"done":
            if(len(str) > 4):
                received_data += str[:-4]
            break
        received_data += str

    data = pickle.loads(received_data)
    return data

def send_stream(conn,data_chunk):
    ssm_dump = pickle.dumps(data_chunk)
    bytes_sent = 0
    while bytes_sent < len(ssm_dump):
        chunk = ssm_dump[bytes_sent:bytes_sent+4096]
        conn.sendall(chunk)
        bytes_sent += len(chunk)
    conn.send(b"done")


def four_fold_key(key):
    leng = len(key)
    dist = leng//4
    arr=[]
    for i in range(0,dist):
        val = 0
        for j in range(i, leng,4):
            val ^= key[j]
        arr.append(val)
        
    lenmissin = 16 - len(arr)
    arr += lenmissin*[0];
    return arr

class QLS_Client:
    #Default Line Ending
    lineending = "\n"

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def send_data(self,host, port):
        self.socket.connect((host, port))
        self.socket.send(b"senddata")
        data = "potatoes"
        ct_bytes = self.cipher1.encrypt(pad(data.encode('utf-8'), AES.block_size))
        send_stream(self.socket,ct_bytes)
        response =recv_stream(self)

    
    def aes_connect(self, host, port):
        self.socket.connect((host, port))
        self.socket.send(b"aesconnectdata")
        self.cipher1 = AES.new(bytes(self.secret_key), AES.MODE_CBC)
        send_stream(self.socket,self.cipher1.iv)
        iv2 = recv_stream(self)
        self.cipher2 =  AES.new(bytes(self.secret_key), AES.MODE_CBC,iv2)
        self.socket.close()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def qkd_connect(self, host,port):
        self._host = host
        self._port = port

        for i in range(0,5):
            self.socket.connect((host, port))
            self.socket.send(b"connectdata")
            received_list =recv_stream(self)
            bob_basis = generate_bits(NUM_QUBITS)
            bob_results = measure_message(received_list, bob_basis)
            send_stream(self.socket,bob_basis)
            alex_basis= recv_stream(self)
            bob_key = remove_garbage(alex_basis,bob_basis,bob_results);
            bob_map_key = select_random_indices(bob_key)
            send_stream(self.socket,bob_map_key)
            response= recv_stream(self)
            self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if response ==  "validdone":
                bob_key = four_fold_key(bob_key)
                self.secret_key = bob_key
                break
            else:
                self.secret_key = False
        if not self.secret_key:
            print("Connection failed")
        else:
            print("Connection succeeded")
            

    def send(self, message: str) -> None:
        self.socket.send(message.encode())

    def recv(self, bufsize=1024) -> str:
        return self.socket.recv(bufsize)
