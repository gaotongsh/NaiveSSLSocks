import socket
from socketserver import ThreadingTCPServer, BaseRequestHandler
import ssl
import sys
from threading import Thread


# The ClientHandler class is a server handler itself.
# It listens to local socks requests and connect to remote SocksServer.
class ClientHandler(BaseRequestHandler):

    @staticmethod
    def forward(src, dst):
        while True:
            ret = src.recv(4096)
            if len(ret) > 0:
                dst.sendall(ret)

    def handle(self):
        local_conn = self.request
        local_request = local_conn.recv(1024)
        while len(local_request) == 0:
            local_request = local_conn.recv(1024)

        # Tell whether it is a valid socks5 connect request.
        if local_request[0] == 0x05:
            nmethods = local_request[1]
            methods = set(local_request[2: 2 + nmethods])

            if 0x00 in methods:
                # Response indicating connect established.
                local_response = bytes([5, 0])
                local_conn.sendall(local_response)

                # Establishing SSL connection with remote RocksServer.
                context = ssl.create_default_context(cafile="cert.pem")
                context.check_hostname = False
                client_conn = context.wrap_socket(socket.socket())
                try:
                    client_conn.connect((sys.argv[2], 1080))
                    t_send = Thread(target=self.forward, args=(local_conn, client_conn))
                    t_send.start()
                    t_recv = Thread(target=self.forward, args=(client_conn, local_conn))
                    t_recv.start()
                    t_send.join()
                    t_recv.join()
                    return
                except OSError:
                    # Establishing SSL connection failure.
                    local_conn.sendall(bytes([5, 4, 0]) + local_request[3:])
                    return

        else:
            local_response = bytes([5, 255])
            local_conn.sendall(local_response)
            return


if __name__ == '__main__':
    print('Welcome to use my proxyClient!')

    if len(sys.argv) != 3:
        print('Usage: python3 proxyClient <local port> <server ip>')
        exit()

    server = ThreadingTCPServer(('localhost', int(sys.argv[1])), ClientHandler)
    server.serve_forever()
