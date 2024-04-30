from qls.qls_server import *

server = QLS_Server()
server.bind("127.0.0.1",4000)

server.listen_and_accept();
