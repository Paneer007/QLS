from qls.qls_server import *

server = QLS_Server()
server.bind("127.0.0.1",3900)

server.listen_and_accept();
