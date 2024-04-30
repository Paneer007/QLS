from qiskit import QuantumCircuit, execute, Aer
from numpy.random import randint
import numpy as np
import socket

NUM_QUBITS = 128

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

def share_basis():
    # TODO:Share the key between two users
    return "the basis"

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


def send_check_keys(key1: list, key2: list) -> None:
    #FIXME: Implement random bit verification 
    print("\nAlice's key: ", key1)
    print("Bob's key:   ", key2)
    if key1 == key2:
        print("Keys are the same and secure.")
    else:
        print("Error: keys are different.")



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
        self.socket.connect((host, port))
    

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