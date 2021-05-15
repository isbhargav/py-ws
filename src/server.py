from gevent import monkey
monkey.patch_all()

import re
from gevent.pool import Pool
from gevent.server import StreamServer

import hashlib
import base64
from io import BytesIO, BufferedRWPair

WS_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Disconnect(Exception):
    pass


class Server:
    def __init__(self, host="127.0.0.1", port=4000, max_clients=64):
        self._pool = Pool(max_clients)
        self._server = StreamServer((host, port), self.connection_handler,
                                    spawn=self._pool)

    def run(self):
        self._server.serve_forever()

    def hand_shake(self, key):
        key = key + WS_MAGIC_STRING
        resp_key = base64.standard_b64encode(hashlib.sha1(key.encode('utf-8'))
                                                    .digest()).decode('utf-8')

        resp = "HTTP/1.1 101 Switching Protocols\r\n" + \
               "Upgrade: websocket\r\n" + \
               "Connection: Upgrade\r\n" + \
               "Sec-WebSocket-Accept: %s\r\n\r\n" % (resp_key)

        return resp

    def decode_frame(self, frame):
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-------+-+-------------+-------------------------------+
        |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        | |1|2|3|       |K|             |                               |
        +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        |     Extended payload length continued, if payload len == 127  |
        + - - - - - - - - - - - - - - - +-------------------------------+
        |                               |Masking-key, if MASK set to 1  |
        +-------------------------------+-------------------------------+
        | Masking-key (continued)       |          Payload Data         |
        +-------------------------------- - - - - - - - - - - - - - - - +
        :                     Payload Data continued ...                :
        + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        |                     Payload Data continued ...                |
        +---------------------------------------------------------------+

        """
        opcode_and_fin = frame[0]
        payload_len = frame[1] - (0b10000000)
        mask = frame[2:6]
        encrypted_payload = frame[6: 6+payload_len]
        payload = bytearray( [ encrypted_payload[i] ^ mask[i % 4] for i in range(payload_len) ] )
        return payload


    def write_response(self, conn, data):
        buf = BytesIO()
        if isinstance(data, str):
            buf.write(bytes(data, 'utf-8'))
        buf.seek(0)
        conn.send(buf.getvalue())
        # socketFile.flush()

    def connection_handler(self, conn, addr):
        req = conn.recv(1024).decode('utf-8').strip().split('\r\n')
        req_method, req_url, req_http = req[0].split()
        headers = {}
        for h in req[1:]:
            if re.match(r"^[a-zA-Z\-]:", h):
                print('match')
            key, val = h.split(':', 1)
            headers[key] = val.strip()

        if "Upgrade" in headers['Connection'] and 'websocket' in headers['Upgrade'] and headers['Sec-WebSocket-Key']:
            key = headers['Sec-WebSocket-Key']
            # Complete Handshake
            resp = self.hand_shake(key)
            self.write_response(conn, resp)

            while True:
                frame = bytearray(conn.recv(1024))
                print(frame)
                payload = self.decode_frame(frame)
                print(payload)
                if payload.decode('utf-8').lower() == 'bye':
                    return conn.close()

        # Not Proper Headers, decline connection upgrade
        else:
            resp = ("HTTP/1.1 400 Bad Request\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Connection: close\r\n" + "\r\n" + "Incorrect request")
            self.write_response(conn, resp)


if __name__ == "__main__":
    port = 4000
    Server(port=port).run()
    print(f"Server Started on Port: {port}")
