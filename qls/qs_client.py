from qiskit import QuantumCircuit, execute, Aer
from numpy.random import randint
import numpy as np
import socket
import pickle
import random

NUM_QUBITS = 128


def select_random_indices(arr):
    num_indices = len(arr) // 4
    random_indices = random.sample(range(len(arr)), num_indices)
    result = {index: arr[index] for index in random_indices}
    return result

def generate_bits(n: int) -> np.ndarray:
    return randint(2, size=n)

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



class QLS_Client:
    #Default Line Ending
    lineending = "\n"

    def __init__(self) -> None:
        """Create a socket connection to given host and port."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host,port):
        """Connects to a given socket port"""
        self._host = host
        self._port = port

        for i in range(0,5):
            self.socket.connect((host, port))
            received_data = b""
            while True:
                str = self.recv()
                if str[-4:] == b"done":
                    if(len(str) > 4):
                        received_data += str[:-4]
                    break
                received_data += str

            received_list = pickle.loads(received_data)
            bob_basis = generate_bits(NUM_QUBITS)
            bob_results = measure_message(received_list, bob_basis)

            ssm_dump = pickle.dumps(bob_basis)
            bytes_sent = 0
            while bytes_sent < len(ssm_dump):
                chunk = ssm_dump[bytes_sent:bytes_sent+4096]
                self.socket.sendall(chunk)
                bytes_sent += len(chunk)
            self.socket.send(b"done")

            received_data = b""
            while True:
                str = self.recv()
                if str[-4:] == b"done":
                    if(len(str) > 4):
                        received_data += str[:-4]
                    break
                received_data += str

            alex_basis = pickle.loads(received_data)
            bob_key = remove_garbage(alex_basis,bob_basis,bob_results);

            bob_map_key = select_random_indices(bob_key)

            ssm_dump = pickle.dumps(bob_map_key)
            bytes_sent = 0
            while bytes_sent < len(ssm_dump):
                chunk = ssm_dump[bytes_sent:bytes_sent+4096]
                self.socket.sendall(chunk)
                bytes_sent += len(chunk)
            self.socket.send(b"done")

            received_data = b""
            while True:
                str = self.recv(1024)
                if str[-4:] == b"done":
                    if(len(str) > 4):
                        received_data += str[:-4]
                    break
                received_data += str
            
            response = pickle.loads(received_data)


            if response ==  "validdone":
                self.secret_key = bob_key
                break
            else:
                self.secret_key = False
                self.socket.close()
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        

        if not self.secret_key:
            print("Connection failed")
        else:
            print("Connection succeeded")

    def send(self, message: str) -> None:
        """Send a string over the socket."""
        self.socket.send(message.encode())

    def send_bytes(self, message: bytes) -> None:
        """Send a bytes object over the socket."""
        self.socket.send(message)

    def recv(self, bufsize=1024) -> str:
        """Recieve a string over the socket."""
        return self.socket.recv(bufsize)

    def recv_bytes(self, bufsize: int = 1024) -> bytes:
        """Recieve a bytes object over the socket."""
        return self.socket.recv(bufsize)

    def duplicate(self):
        """Returns a new QLS object of the same host and port."""
        return QLS_Client(self._host, self._port)

    def close(self) -> None:
        """Closes the socket."""
        self.socket.close()