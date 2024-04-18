import socket

class QLS_Server:
    #Default Line Ending
    lineending = "\n"

    def __init__(self) -> None:
        """Create a socket connection"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host,port):
        """Connects to a given socket port"""
        self._host = host
        self._port = port
        self.socket.connect((host, port))

    def bind(self, host,port):
        """binds to a given address"""
        self._host = host
        self._port = port
        self.socket.bind((host, port))
    
    def listen_and_accept(self):
        """Listens and accepts a request a given socket port"""
        conn, addr = self.socket.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)

    def send(self, message: str) -> None:
        """Send a string over the socket."""
        if message[-len(self.lineending):] != self.lineending:
            message += self.lineending
        self.socket.send(message.encode())

    def send_bytes(self, message: bytes) -> None:
        """Send a bytes object over the socket."""
        if message[-len(self.lineending.encode()):] != self.lineending.encode():
            message += self.lineending.encode()
        self.socket.send(message)

    def recv(self, bufsize=1024) -> str:
        """Recieve a string over the socket."""
        return self.socket.recv(bufsize).decode()

    def recv_bytes(self, bufsize: int = 1024) -> bytes:
        """Recieve a bytes object over the socket."""
        return self.socket.recv(bufsize)

    def ignore(self, number_of_lines: int = 1, bufsize: int = 1024) -> None:
        """Recieve and ignore the specified bufsize of lines from the socket."""
        for _ in range(0, number_of_lines):
            self.socket.recv(bufsize)

    def set_line_ending(self, lineending: str) -> None:
        """Change the default line ending"""
        self.lineending = lineending

    def duplicate(self):
        """Returns a new QLS object of the same host and port."""
        return QLS_Server(self._host, self._port)

    def close(self) -> None:
        """Closes the socket."""
        self.socket.close()