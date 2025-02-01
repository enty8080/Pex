"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import errno
import struct
import socket

from typing import Union, Any, Callable
from .packet import TLVPacket

from pex.proto.http import HTTPListener
from pex.string import String


class TLVServerHTTP(object):
    """ Subclass of pex.proto.tlv module.

    This subclass of pex.proto.tlv module represents Python
    implementation of the TLV HTTP server.
    """

    def __init__(self, server: HTTPListener, callback: Callable[[TLVPacket], None] = None,
                 urlpath: str = '/') -> None:
        """ Initialize TLVClient with socket.

        :param HTTPListener server: server
        :param Callable[[TLVpacket], None] callback: method that is executed on HTTP method
        (NOTE: method should take one argument - TLVPacket)
        :param str urlpath: URL path
        :return None: None
        """

        self.server = server
        self.callback = callback
        self.urlpath = urlpath
        self.egress = b''

        def get(request: Any) -> None:
            """ GET request handler to send commands to client.

            :param Any request: request instance
            :return None: None
            """

            if request.path != self.urlpath:
                return

            request.send_status(200)
            request.wfile.write(self.egress)

            self.egress = b''

        def post(request: Any) -> None:
            """ POST request handler to receive from client.

            :param Any request: request instance
            :return None: None
            """

            if request.path != self.urlpath:
                return

            length = int(request.headers['Content-Length'])
            data = request.rfile.read(length)

            request.send_status(200)

            try:
                request.wfile.write(self.egress)
            except Exception:
                pass

            if self.callback:
                self.callback(TLVPacket(data))

        self.server.methods.update({
            self.urlpath: {
                'GET': get,
                'POST': post
            }
        })

        self.get = get
        self.post = post

    def set_urlpath(self, urlpath: str) -> None:
        """ Set URL path.

        :param str urlpath: URL path to set
        :return None: None
        """

        self.server.methods.pop(self.urlpath)
        self.urlpath = '/' + urlpath

        self.server.methods.update({
            self.urlpath: {
                'GET': self.get,
                'POST': self.post
            }
        })

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet to the client.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        self.egress += packet.buffer

    def close(self) -> None:
        """ Close and stop server.

        :return None: None
        """

        self.server.methods.pop(self.urlpath)


class TLVClient(object):
    """ Subclass of pex.proto.tlv module.

    This subclass of pex.proto.tlv module represents Python
    implementation of the TLV client.
    """

    def __init__(self, client: socket.socket) -> None:
        """ Initialize TLVClient with socket.

        :param socket.socket client: socket
        :return None: None
        """

        self.client = client

    def close(self) -> None:
        """ Close connected socket.

        :return None: None
        """

        if self.client:
            self.client.close()

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet to the socket.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        self.send_raw(packet.buffer)

    def read(self, block: bool = True) -> Union[TLVPacket, None]:
        """ Read TLV packet from the socket.

        :return Union[TLVPacket, None]: read TLV packet
        (returns None in case of blocking I/O)
        :param bool block: True to block socket else False
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        self.client.setblocking(block)
        buffer = b''

        try:
            buffer = self.read_raw(4)
        except socket.error as e:
            if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                return

        self.client.setblocking(True)
        length = self.read_raw(4)

        buffer += length
        length = struct.unpack('!I', length)[0]

        value = b''

        while length > 0:
            chunk = self.read_raw(length)
            value += chunk
            length -= len(chunk)

        buffer += value

        return TLVPacket(buffer=buffer)

    def send_raw(self, data: bytes) -> None:
        """ Send raw data instead of TLV packet.

        :param bytes data: data to send
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        while data:
            try:
                sent = self.client.send(data)
                data = data[sent:]

            except socket.error as e:
                if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    continue

    def read_raw(self, size: int) -> bytes:
        """ Read raw data instead of TLV packet.

        :param int size: size of data to read
        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        return self.client.recv(size)
