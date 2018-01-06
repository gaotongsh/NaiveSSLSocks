from ipaddress import IPv4Address, IPv6Address
import socket
from socketserver import BaseRequestHandler, TCPServer, ThreadingMixIn
import ssl
import sys
from threading import Thread


# The MySSLSocksServer class is a server.
# With the ability to wrap a socket into a SSL socket.
class MySSLSocksServer(TCPServer):

    def __init__(self, server_address, request_handler_class):
        super().__init__(server_address, request_handler_class)
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    def get_request(self):
        new_socket, from_address = self.socket.accept()
        ssl_socket = self.context.wrap_socket(new_socket, server_side=True)
        return ssl_socket, from_address


# The ServerHandler class handles income SSL sockets.
class ServerHandler(BaseRequestHandler):

    @staticmethod
    def forward(src, dst):
        while True:
            ret = src.recv(4096)
            if len(ret) > 0:
                dst.sendall(ret)

    def handle(self):
        ssl_conn = self.request
        ssl_request = ssl_conn.recv(1024)
        while len(ssl_request) == 0:
            ssl_request = ssl_conn.recv(1024)

        # Tell whether it is a valid socks5 CONNECT request.
        if ssl_request[0] == 0x05 and ssl_request[1] == 0x01:
            address_type = ssl_request[3]

            # Connection to an IPv4 address.
            if address_type == 0x01:
                addr = str(IPv4Address(ssl_request[4: 8]))
            # Connection to a domain name.
            elif address_type == 0x03:
                noctets = ssl_request[4]
                addr = ssl_request[5: 5 + noctets].decode('UTF-8', 'strict')
            # Connection to an IPv6 address.
            elif address_type == 0x04:
                addr = str(IPv6Address(ssl_request[4: 20]))

            port = ssl_request[-2] * 256 + ssl_request[-1]

            print(addr, port)

            # Establishing connection with remote server.
            client_conn = socket.socket()
            try:
                client_conn.connect((addr, port))
                # Setting up socks5 connection success.
                ssl_conn.sendall(bytes([5, 0, 0]) + ssl_request[3:])
                t_send = Thread(target=self.forward, args=(ssl_conn, client_conn))
                t_send.start()
                t_recv = Thread(target=self.forward, args=(client_conn, ssl_conn))
                t_recv.start()
                t_send.join()
                t_recv.join()
                return
            except OSError:
                # Establishing socks5 connection failure.
                ssl_conn.sendall(bytes([5, 5, 0]) + ssl_request[3:])
                return

        # Connection refused.
        ssl_response = bytes((bytes([5, 5, 0]) + ssl_request[3:]))
        ssl_conn.sendall(ssl_response)
        return


class MyThreadingSSLTCPServer(ThreadingMixIn, MySSLSocksServer):
    pass


if __name__ == '__main__':
    print('Welcome to use my proxyServer!')

    if len(sys.argv) != 2:
        print('Usage: python3 proxyServer <server ip>')
        exit()

    server = MyThreadingSSLTCPServer((sys.argv[1], 1080), ServerHandler)
    print("Server starts on " + sys.argv[1] + ":1080")
    server.serve_forever()
