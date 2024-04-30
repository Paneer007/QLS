from qls.qs_client import * 
import random
import pickle

def select_random_indices(arr):
    num_indices = len(arr) // 4
    random_indices = random.sample(range(len(arr)), num_indices)
    result = {index: arr[index] for index in random_indices}
    return result

client = QLS_Client()

client.connect("127.0.0.1",5000)
received_data = b""
while True:
    str = client.recv()
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
    client.socket.sendall(chunk)
    bytes_sent += len(chunk)
client.socket.send(b"done")

received_data = b""
while True:
    str = client.recv()
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
    client.socket.sendall(chunk)
    bytes_sent += len(chunk)
print(bob_key)
client.socket.send(b"done")

