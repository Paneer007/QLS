from qiskit import execute, Aer
from numpy.random import randint
import numpy as np
import socket
import pickle
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

NUM_QUBITS = 96


def select_random_indices(arr: list) -> list:
    """
    Randomly selects indices from an array.

    Parameters:
        arr (list): The array from which indices will be selected.

    Returns:
        dict: A dictionary containing randomly selected indices and their corresponding values.
    """
    num_indices = len(arr) // 4
    random_indices = random.sample(range(len(arr)), num_indices)
    result = {index: arr[index] for index in random_indices}
    return result


def generate_bits(n: int) -> np.ndarray:
    """
    Generates an array of random binary bits.

    Parameters:
        n (int): The length of the array, indicating the number of bits to generate.

    Returns:
        np.ndarray: An array of random binary bits of length 'n'.
    """
    return randint(2, size=n)


def measure_message(message: list, basis: np.ndarray) -> list:
    """
    Measures a quantum message.

    Parameters:
        message (list): A list of quantum bits representing the message.
        basis (np.ndarray): An array indicating the measurement bases.

    Returns:
        list: A list containing the measured results.
    """
    backend = Aer.get_backend(
        "qasm_simulator")  # obtain the simulator for noise in the qubits
    measurements = []
    for q in range(NUM_QUBITS):
        if basis[q] == 1:  # Check if the measurement basis is 1 (X-basis)
            # Apply a Hadamard gate to prepare the qubit in the X-basis
            message[q].h(0)
        # Measure the qubit and store the result in classical bit 0
        message[q].measure(0, 0)
        # Execute the quantum circuit
        result = execute(message[q], backend, shots=1, memory=True).result()
        # Append the measurement result to the list of measurements
        measurements.append(int(result.get_memory()[0]))
    return measurements


def remove_garbage(a_basis: np.ndarray, b_basis: np.ndarray, bits: np.ndarray) -> list:
    """
    Removes garbage bits based on matching bases.

    Parameters:
        a_basis (np.ndarray): Alice's measurement bases.
        b_basis (np.ndarray): Bob's measurement bases.
        bits (np.ndarray): The received bits.

    Returns:
        list: The filtered bits.
    """
    return [bits[q] for q in range(NUM_QUBITS) if a_basis[q] == b_basis[q]]


def recv_stream(conn: any) -> any:
    """
    Receives streamed data over a connection.

    Parameters:
        conn: The connection object.

    Returns:
        Any: The received data.
    """
    received_data = b""
    while True:
        str = conn.recv()
        if str[-4:] == b"done":
            if (len(str) > 4):
                received_data += str[:-4]
            break
        received_data += str

    data = pickle.loads(received_data)
    return data


def send_stream(conn, data_chunk: any) -> None:
    """
    Sends data chunk over a connection in a streamed manner.

    Parameters:
        conn (socket.socket): The connection object.
        data_chunk (Any): The data chunk to be sent.
    """
    ssm_dump = pickle.dumps(data_chunk)
    bytes_sent = 0
    while bytes_sent < len(ssm_dump):
        chunk = ssm_dump[bytes_sent:bytes_sent+4096]
        conn.sendall(chunk)
        bytes_sent += len(chunk)
    conn.send(b"done")


def four_fold_key(key: list) -> list:
    """
    Performs four-fold key transformation. Allows us to mask bits which are publically announced

    Parameters:
        key (list): The key to be transformed.

    Returns:
        list: The transformed key.
    """
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


class QLS_Client:

    def __init__(self) -> None:
        """
        Initializes a QLS Client instance.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_data(self, host, port):
        """
        Sends data over a connection.

        Parameters:
            host (str): The host address.
            port (int): The port number.
        """
        self.socket.connect((host, port))
        self.socket.send(b"senddata")

        data = input("> ")

        # Encrypt the input data using AES encryption with the cipher1 object
        ct_bytes = self.cipher1.encrypt(
            pad(data.encode('utf-8'), AES.block_size))

        print("CT Text: ", ct_bytes)
        send_stream(self.socket, ct_bytes)
        self.socket.close()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def aes_connect(self, host, port):
        """
        Establishes an AES connection.

        Parameters:
            host (str): The host address.
            port (int): The port number.
        """
        self.socket.connect((host, port))
        self.socket.send(b"aesconnectdata")

        # Initialize cipher1 object with AES encryption using the secret key in CBC mode
        self.cipher1 = AES.new(bytes(self.secret_key), AES.MODE_CBC)

        # Send the initialization vector (IV) of cipher1 over the socket using send_stream function
        send_stream(self.socket, self.cipher1.iv)

        # Receive the initialization vector (IV) for cipher2 from the socket using recv_stream function
        iv2 = recv_stream(self)

        # Initialize cipher2 object with AES encryption using the secret key and received IV in CBC mode
        self.cipher2 = AES.new(bytes(self.secret_key), AES.MODE_CBC, iv2)

        self.socket.close()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def qkd_connect(self, host, port):
        """
        Establishes a QKD connection.

        Parameters:
            host (str): The host address.
            port (int): The port number.
        """
        self._host = host
        self._port = port

        # Iterate 5 times to attempt connection
        for i in range(0, 5):
            self.socket.connect((host, port))
            self.socket.send(b"connectdata")

            # Receive alice from the socket and store it as a list
            alice_message = recv_stream(self)

            # Generate random bit string as Bob's measurement basis
            bob_basis = generate_bits(NUM_QUBITS)

            # Measure the received quantum message using Bob's basis
            bob_results = measure_message(alice_message, bob_basis)

            # Send Bob's measurement basis over the socket
            send_stream(self.socket, bob_basis)

            # Receive Alice's measurement basis from the socket
            alice_basis = recv_stream(self)

            # Remove garbage bits and obtain Bob's key
            bob_key = remove_garbage(alice_basis, bob_basis, bob_results)

            # Randomly select bits from Bob's key to create a publicly announced map key
            bob_map_key = select_random_indices(bob_key)

            # Send Bob's map key over the socket
            send_stream(self.socket, bob_map_key)

            response = recv_stream(self)
            self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if response == "validdone":
                # Perform 4-fold key compression
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
        """
        Sends a message.

        Parameters:
            message (str): The message to send.
        """
        self.socket.send(message.encode())

    def recv(self, bufsize=1024) -> str:
        """
        Receives a message.

        Parameters:
            bufsize (int): The buffer size for receiving.

        Returns:
            str: The received message.
        """
        return self.socket.recv(bufsize)
