from qls.qs_client import * 
import pickle

client = QLS_Client()

client.connect("127.0.0.1",4000)
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

print(bob_key);
