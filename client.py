from qls.qs_client import * 
import pickle

client = QLS_Client()

client.connect("127.0.0.1",5000)
received_data = b""
while True:
    print("next round")
    str = client.recv()
    print(str)
    if str[-4:] == b"done":
        if(len(str) > 4):
            received_data += str[:-4]
        break
    received_data += str

print(received_data,)
received_list = pickle.loads(received_data)
print("done")
print(received_list)
bob_basis = generate_bits(NUM_QUBITS)
bob_results = measure_message(received_list, bob_basis)
print(bob_results)

client.send("");

