from qiskit import QuantumCircuit, execute, Aer
from numpy.random import randint
import numpy as np
import socket
import pickle


NUM_QUBITS = 1024

def generate_bits(n: int) -> np.ndarray:
    """
    Generate an array of random bits.

    Parameters:
    n (int): The number of bits to generate.

    Returns:
    np.ndarray: An array of random bits.
    """
    return randint(2, size=n)

def encode_message(bits: np.ndarray, basis: np.ndarray) -> list:
    message = []
    for i in range(NUM_QUBITS):
        qc = QuantumCircuit(1, 1) # 1 qubit and 1 classical bit - message and measurement respectively
        if basis[i] == 0:  # Prepare qubit in Z-basis (i.e. |0> or |1>)
            if bits[i] == 1:
                qc.x(0) # Bit flip (Pauli-X gate)
        else:  # Prepare qubit in X-basis (i.e. |+> or |->)
            if bits[i] == 0:
                qc.h(0) # Hadamard gate
            else:
                qc.x(0)
                qc.h(0)
        qc.barrier()
        message.append(qc)
    return message

def simulate_quantum_channel(message: list, error_rate: float) -> list:
    noisy_message = []
    for qc in message:
        if np.random.random() < error_rate:  # Bit flip with given error rate
            qc.x(0)
        noisy_message.append(qc)
    return noisy_message

def remove_garbage(a_basis: np.ndarray, b_basis: np.ndarray, bits: np.ndarray) -> list:
    """
    Remove bits that were measured in different bases.

    Parameters:
    a_basis (np.ndarray): The basis used by the first party.
    b_basis (np.ndarray): The basis used by the second party.
    bits (np.ndarray): The bits to be filtered.

    Returns:
    list: The filtered bits.
    """
    return [bits[q] for q in range(NUM_QUBITS) if a_basis[q] == b_basis[q]]  # Removes bits that do not match


def measure_message(message: list, basis: np.ndarray) -> list:
    """
    Measure a quantum message using a given basis.

    Parameters:
    message (list): The quantum message to be measured.
    basis (np.ndarray): The basis to use for measurement.

    Returns:
    list: The measurements results.
    """
    backend = Aer.get_backend("qasm_simulator")
    measurements = []
    for q in range(NUM_QUBITS):
        if basis[q] == 1:  # Measuring in X-basis
            message[q].h(0)
        message[q].measure(0, 0)
        result = execute(message[q], backend, shots=1, memory=True).result()
        measurements.append(int(result.get_memory()[0]))
    return measurements

def check_keys(key1: list, key2: list) -> None:
    """
    Check if two keys are the same.

    Parameters:
    key1 (list): The first key to be compared.
    key2 (list): The second key to be compared.

    Returns:
    None
    """
    print("\nAlice's key: ", key1)
    print("Bob's key:   ", key2)
    if key1 == key2:
        print("Keys are the same and secure.")
    else:
        print("Error: keys are different.")


class QLS_Server:
    #Default Line Ending
    lineending = "\n"

    def __init__(self) -> None:
        """Create a socket connection"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def bind(self, host,port):
        """binds to a given address"""
        self._host = host
        self._port = port
        self.socket.bind((host, port))
        self.socket.listen(0)
    
    def listen_and_accept(self): #establishes QLS with the client before sending more requests
        """Listens and accepts a request a given socket port"""
        while True:
            conn, addr = self.socket.accept()
            secret = generate_bits(NUM_QUBITS)
            secret_basis = generate_bits(NUM_QUBITS) #TODO: implement four tone key checking
            secret_message = encode_message(secret, secret_basis)
            secret_sent_message = simulate_quantum_channel(secret_message,0)
            with conn:
                ssm_dump = pickle.dumps(secret_sent_message)
                bytes_sent = 0
                while bytes_sent < len(ssm_dump):
                    chunk = ssm_dump[bytes_sent:bytes_sent+4096]
                    conn.sendall(chunk)
                    bytes_sent += len(chunk)
                conn.send(b"done")
                print(f"Connected by {addr}")
                # while True:
                #     data = conn.recv(1024)
                #     if not data:
                #         break
                #     conn.sendall(data)
                received_data = b""
                while True:
                    str = conn.recv(1024)
                    if str[-4:] == b"done":
                        if(len(str) > 4):
                            received_data += str[:-4]
                        break
                    received_data += str
                bob_basis = pickle.loads(received_data)
                print(bob_basis)


                alex_basis = pickle.dumps(secret_basis)
                bytes_sent = 0
                while bytes_sent < len(alex_basis):
                    chunk = alex_basis[bytes_sent:bytes_sent+4096]
                    conn.sendall(chunk)
                    bytes_sent += len(chunk)
                conn.send(b"done")

                alex_key = remove_garbage(secret_basis,bob_basis,secret )
                print(alex_key)


    def send(self, message: str) -> None:
        """Send a string over the socket."""
        if message[-len(self.lineending):] != self.lineending:
            message += self.lineending
        self.socket.send(message.encode())

    def send_bytes(self, message: bytes) -> None:
        """Send a bytes object over the socket."""
        if message[-len(self.lineending.encode()):] != self.lineending.encode():
            message += self.lineending.encode()
        self.socket.send(message)

    def recv(self, bufsize=1024) -> str:
        """Recieve a string over the socket."""
        return self.socket.recv(bufsize).decode()

    def recv_bytes(self, bufsize: int = 1024) -> bytes:
        """Recieve a bytes object over the socket."""
        return self.socket.recv(bufsize)


    def close(self) -> None:
        """Closes the socket."""
        self.socket.close()