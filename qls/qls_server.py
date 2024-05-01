from qiskit import QuantumCircuit, execute, Aer
from numpy.random import randint
import numpy as np
import socket
import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad

NUM_QUBITS = 96


def generate_bits(n: int) -> np.ndarray:
    return randint(2, size=n)


def four_fold_key(key):
    leng = len(key)
    dist = leng//4
    arr = []
    for i in range(0, dist):
        val = 0
        for j in range(i, leng, 4):
            val ^= key[j]
        arr.append(val)

    lenmissin = 16 - len(arr)
    arr += lenmissin*[0]
    return arr


def encode_message(bits: np.ndarray, basis: np.ndarray) -> list:
    message = []
    for i in range(NUM_QUBITS):
        # 1 qubit and 1 classical bit - message and measurement respectively
        qc = QuantumCircuit(1, 1)
        if basis[i] == 0:  # Prepare qubit in Z-basis (i.e. |0> or |1>)
            if bits[i] == 1:
                qc.x(0)  # Bit flip (Pauli-X gate)
        else:  # Prepare qubit in X-basis (i.e. |+> or |->)
            if bits[i] == 0:
                qc.h(0)  # Hadamard gate
            else:
                qc.x(0)
                qc.h(0)
        qc.barrier()
        message.append(qc)
    return message


def simulate_quantum_channel(message: list, error_rate: float) -> list:
    noisy_message = []
    for qc in message:
        if np.random.random() < error_rate:
            qc.x(0)
        noisy_message.append(qc)
    return noisy_message


def remove_garbage(a_basis: np.ndarray, b_basis: np.ndarray, bits: np.ndarray) -> list:
    return [bits[q] for q in range(NUM_QUBITS) if a_basis[q] == b_basis[q]]


def check_keys(map, key2: list) -> bool:
    global flag
    flag = True

    for key, value in map.items():
        if key2[key] != value:
            flag = False
            break
    if flag:
        print("Keys are the same and secure.")
    else:
        print("Error: keys are different.")

    return flag


def recv_stream(conn):
    received_data = b""
    while True:
        str = conn.recv(1024)
        if str[-4:] == b"done":
            if (len(str) > 4):
                received_data += str[:-4]
            break
        received_data += str
    data = pickle.loads(received_data)
    return data


def send_stream(conn, data_chunk):
    ssm_dump = pickle.dumps(data_chunk)
    bytes_sent = 0
    while bytes_sent < len(ssm_dump):
        chunk = ssm_dump[bytes_sent:bytes_sent+4096]
        conn.sendall(chunk)
        bytes_sent += len(chunk)
    conn.send(b"done")


class QLS_Server:
    # Default Line Ending
    lineending = "\n"

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def bind(self, host, port):
        self._host = host
        self._port = port
        self.socket.bind((host, port))
        self.socket.listen(0)

    def aes_connect(self, conn, addr):
        iv1_key = recv_stream(conn)
        self.cipher1 = AES.new(bytes(self.aes_key), AES.MODE_CBC, iv1_key)
        self.cipher2 = AES.new(bytes(self.aes_key), AES.MODE_CBC)
        send_stream(conn, self.cipher2.iv)
        pass

    def recv_data(self, conn, addr):
        ciphertext = recv_stream(conn)
        pt = unpad(self.cipher1.decrypt(ciphertext), AES.block_size)
        print("The message was: ", pt.decode('utf-8'))

    def qls_connect(self, conn, addr):
        secret = generate_bits(NUM_QUBITS)
        # TODO: implement four tone key checking
        secret_basis = generate_bits(NUM_QUBITS)
        secret_message = encode_message(secret, secret_basis)
        secret_sent_message = simulate_quantum_channel(secret_message, 0.01)
        with conn:
            send_stream(conn, secret_sent_message)
            bob_basis = recv_stream(conn)
            send_stream(conn, secret_basis)
            alex_key = remove_garbage(secret_basis, bob_basis, secret)
            bob_map_key = recv_stream(conn)
            res = check_keys(bob_map_key, alex_key)
            status = ""
            if res:
                alex_key = four_fold_key(alex_key)
                self.aes_key = alex_key
                status = "validdone"
            else:
                status = "repeatdone"
            send_stream(conn, status)

    # establishes QLS with the client before sending more requests

    def listen_and_accept(self):
        while True:
            conn, addr = self.socket.accept()
            type = conn.recv(1024).decode()
            if type == "connectdata":
                self.qls_connect(conn, addr)
            elif type == "aesconnectdata":
                self.aes_connect(conn, addr)
            elif type == "senddata":
                self.recv_data(conn, addr)
            else:
                print("Skill issue")

    def send(self, message: str) -> None:
        self.socket.send(message.encode())

    def send_bytes(self, message: bytes) -> None:
        self.socket.send(message)

    def recv(self, bufsize=1024) -> str:
        return self.socket.recv(bufsize).decode()
