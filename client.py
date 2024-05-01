from qls.qs_client import * 
import random
import pickle



client = QLS_Client()

client.qkd_connect("127.0.0.1",3400)

client.aes_connect("127.0.0.1",3400)

client.send_data("127.0.0.1",3400)

