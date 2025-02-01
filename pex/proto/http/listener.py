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

import http.server
import socketserver

from typing import Any

from .tools import HTTPTools


class PrimitiveServer(socketserver.TCPServer):
    """ Subclass of pex.proto.http module.

    This subclass of pex.proto.http module represents
    HTTP/TCP server.
    """

    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)


class PrimitiveHandler(http.server.SimpleHTTPRequestHandler):
    """ Subclass of pex.proto.http module.

    This subclass of pex.proto.http module represents
    HTTP handler for web server.
    """

    def log_request(self, fmt, *args) -> None:
        pass

    def send_status(self, code: int = 200) -> None:
        self.send_response(int(code))
        self.send_header("Content-type", "text/html")
        self.end_headers()


class HTTPListener(object):
    """ Subclass of pex.proto.http module.

    This subclass of pex.proto.http module represents Python
    implementation of HTTP listener.
    """

    def __init__(self, host: str, port: int, methods: dict = {}) -> None:
        """ Start HTTP listener on socket pair.

        NOTE: methods should look like this:
            {
                'urlpath1': {
                    'get': get,
                    'post': post,
                },
                ...
            }

        :param str host: host to listen
        :param int port: port to listen
        :param dict methods: methods, method classes containing
        method names as keys and method handlers as items
        :return None: None
        """

        self.http_tools = HTTPTools()
        self.handler = PrimitiveHandler

        self.host = host
        self.port = int(port)
        self.server = (host, port)

        self.sock = None
        self.methods = methods

        def get(request: Any) -> None:
            """ GET request handler.

            :param Any request: request instance
            :return None: None
            """

            method = self.methods.get(request.path, None)

            if not method:
                request.send_status(404)
                return

            callback = method.get('GET', None)

            if callback:
                callback(request)

        def post(request: Any) -> None:
            """ POST request handler.

            :param Any request: request instance
            :return None: None
            """

            method = self.methods.get(request.path, None)

            if not method:
                request.send_status(404)
                return

            callback = method.get('POST', None)

            if callback:
                callback(request)

        self.handler.do_GET = get
        self.handler.do_POST = post

    def listen(self) -> None:
        """ Start HTTP listener.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock = PrimitiveServer((self.host, self.port), self.handler)
            self.running = True
        except Exception:
            raise RuntimeError(f"Failed to start HTTP listener on port {str(self.port)}!")

    def stop(self) -> None:
        """ Stop HTTP listener.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.running = False

        try:
            self.sock.server_close()
        except Exception:
            raise RuntimeError(f"HTTP listener is not started!")

    def accept(self) -> None:
        """ Accept connection.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.handle_request()
        except Exception:
            raise RuntimeError(f"HTTP listener is not started!")

    def loop(self) -> None:
        """ Event loop.

        :return None: None
        """

        while self.running:
            try:
                self.sock.accept()

            except Exception:
                self.stop()
