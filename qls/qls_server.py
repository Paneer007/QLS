from qiskit import QuantumCircuit
from numpy.random import randint
import numpy as np
import socket
import pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

NUM_QUBITS = 96


def generate_bits(n: int) -> np.ndarray:
    """
    Generates an array of random binary bits.

    Parameters:
        n (int): The length of the array, indicating the number of bits to generate.

    Returns:
        np.ndarray: An array of random binary bits of length 'n'.
    """
    return randint(2, size=n)


def four_fold_key(key: list) -> list:
    """
    Splits a key into four equal parts and performs XOR operation on each part.

    Parameters:
        key (list): The input key to be processed.

    Returns:
        list: A list containing four values obtained by XOR-ing every fourth element of the input key.
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


def encode_message(bits: np.ndarray, basis: np.ndarray) -> list:
    """
    Encodes a message using quantum circuits based on given bits and bases.

    Parameters:
        bits (np.ndarray): An array containing the bits to be encoded.
        basis (np.ndarray): An array indicating the bases for encoding.

    Returns:
        list: A list of quantum bits representing the encoded message.
    """
    message = []
    for i in range(NUM_QUBITS):
        # 1 qubit and 1 classical bit - message and measurement respectively
        qc = QuantumCircuit(1, 1)
        if basis[i] == 0:  # Prepare qubit in Z-basis (i.e. |0> or |1>)
            if bits[i] == 1:
                qc.x(0)  # Bit flip (Pauli-X gate)
        else:  # Prepare qubit in X-basis (i.e. |+> or |->)
            if bits[i] == 0:
                qc.h(0)  # Hadamard gate for |+>
            else:
                qc.x(0)
                qc.h(0)  # Hadamard + Pauli-X gate for |->
        qc.barrier()
        message.append(qc)
    return message


def simulate_quantum_channel(message: list, error_rate: float) -> list:
    """
    Simulates a quantum channel by introducing errors to the encoded message.

    Parameters:
        message (list): A list of quantum circuits representing the encoded message.
        error_rate (float): The probability of introducing an error to each qubit.

    Returns:
        list: A list of quantum bits representing the noisy message after error introduction.
    """
    noisy_message = []
    for qc in message:
        if np.random.random() < error_rate:  # randomly creates a probability and checks if it is less than the threshold
            qc.x(0)
        noisy_message.append(qc)
    return noisy_message


def remove_garbage(a_basis: np.ndarray, b_basis: np.ndarray, bits: np.ndarray) -> list:
    """
    Removes garbage bits from the received bits based on matching bases.

    Parameters:
        a_basis (np.ndarray): An array representing Alice's measurement bases.
        b_basis (np.ndarray): An array representing Bob's measurement bases.
        bits (np.ndarray): An array containing the received bits.

    Returns:
        list: A list containing the bits that were measured with matching bases by Alice and Bob.
    """
    return [bits[q] for q in range(NUM_QUBITS) if a_basis[q] == b_basis[q]]


def check_keys(map: dict, key2: list) -> bool:
    """
    Checks if two keys are identical.

    Parameters:
        map (dict): A dictionary representing a key mapping of announced public key.
        key2 (list): The Alice key to compare with the key in the mapping.

    Returns:
        bool: True if the keys are identical, False otherwise.
    """
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


def recv_stream(conn: any) -> any:
    """
    Receive streamed data over a connection.

    Parameters:
        conn: The connection object.

    Returns:
        The received data.
    """
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


def send_stream(conn, data_chunk) -> None:
    """
    Send data chunk over a connection in a streamed manner.

    Parameters:
        conn: The connection object.
        data_chunk: The data chunk to be sent.
    """
    data_dump = pickle.dumps(
        data_chunk)  # enccoding the data to a binary format
    bytes_sent = 0
    # keep sending data till all the data is transmitted
    while bytes_sent < len(data_dump):
        chunk = data_dump[bytes_sent:bytes_sent+4096]
        conn.sendall(chunk)
        bytes_sent += len(chunk)
    conn.send(b"done")


class QLS_Server:

    def __init__(self) -> None:
        """
            Initializes a QLS Server instance.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def bind(self, host, port) -> None:
        """
        Binds the server to a specified host and port.

        Parameters:
            host (str): The host address to bind.
            port (int): The port number to bind.
        """
        self._host = host
        self._port = port
        self.socket.bind((host, port))
        self.socket.listen(0)

    def aes_connect(self, conn) -> None:
        """
        Establishes an AES connection.

        Parameters:
            conn: The connection object.
            addr: The address of the connected client.
        """
        iv1_key = recv_stream(conn)  # obtain initialisation vector from client
        # creates decryption cipher
        self.cipher1 = AES.new(bytes(self.aes_key), AES.MODE_CBC, iv1_key)
        # creates encryption cipher
        self.cipher2 = AES.new(bytes(self.aes_key), AES.MODE_CBC)
        send_stream(conn, self.cipher2.iv)

    def recv_data(self, conn) -> None:
        """
        Receives encrypted data and decrypts it.

        Parameters:
            conn: The connection object.
            addr: The address of the connected client.
        """
        ciphertext = recv_stream(conn)
        pt = unpad(self.cipher1.decrypt(ciphertext), AES.block_size)
        print("The message was: ", pt.decode('utf-8'))

    def qls_connect(self, conn) -> None:
        """
        Establishes a QLS connection.

        Parameters:
            conn: The connection object.
            addr: The address of the connected client.
        """
        # Generate secret to be sent via quantum channel
        secret = generate_bits(NUM_QUBITS)

        # Generate Alice's basis vector
        alice_basis = generate_bits(NUM_QUBITS)

        # Encode the secret using quantum states
        secret_quantum_encoded = encode_message(secret, alice_basis)

        # Simulate noise in the quantum channel
        secret_sent_message = simulate_quantum_channel(
            secret_quantum_encoded, 0.01)

        with conn:
            # Send the secret message via the quantum channel
            send_stream(conn, secret_sent_message)

            # Receive Bob's basis
            bob_basis = recv_stream(conn)

            # Send Alice's basis to Bob
            send_stream(conn, alice_basis)

            # Check if any of the keys do not match
            alice_key = remove_garbage(alice_basis, bob_basis, secret)

            # Obtain publicly announced key from Bob
            bob_map_key = recv_stream(conn)

            # Check if the keys match
            res = check_keys(bob_map_key, alice_key)
            status = ""
            if res:
                # Perform 4-fold key compression
                alice_key = four_fold_key(alice_key)
                self.aes_key = alice_key
                status = "validdone"
            else:
                status = "repeatdone"
            send_stream(conn, status)

    def listen_and_accept(self):
        """
        Listens for incoming connections and accepts them.
        """
        while True:
            conn, addr = self.socket.accept()
            print(f"connected by {addr}")
            type = conn.recv(1024).decode()
            # when client wants to connect to the server
            if type == "connectdata":
                self.qls_connect(conn)
            # when client wants to perform aes des exchange
            elif type == "aesconnectdata":
                self.aes_connect(conn)
            # when client wants to send messages back and forth to the server
            elif type == "senddata":
                self.recv_data(conn)
            else:
                print("Skill issue")

    def send(self, message: str) -> None:
        """
        Sends a message.

        Parameters:
            message (str): The message to send.
        """
        self.socket.send(message.encode())

    def send_bytes(self, message: bytes) -> None:
        """
        Sends bytes.

        Parameters:
            message (bytes): The bytes to send.
        """
        self.socket.send(message)

    def recv(self, bufsize=1024) -> str:
        """
        Receives a message.

        Parameters:
            bufsize (int): The buffer size for receiving.

        Returns:
            str: The received message.
        """
        return self.socket.recv(bufsize).decode()
