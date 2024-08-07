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

import ftplib
import io


class FTPClient(object):
    """ Subclass of pex.proto.ftp module.

    This subclass of pex.proto.ftp module represents Python
    implementation of the FTP client.
    """

    def __init__(self, host: str, port: int, timeout: int = 10, ssl: bool = False) -> None:
        """ Initialize FTPClient with socket pair.

        :param str host: FTP host
        :param int port: FTP port
        :param int timeout: connection timeout
        :param bool ssl: True if FTP uses SSL else False
        :return None: None
        """

        self.host = host
        self.port = int(port)

        self.pair = f"{self.host}:{str(self.port)}"
        self.timeout = float(timeout)

        if ssl:
            self.client = ftplib.FTP_TLS()
        else:
            self.client = ftplib.FTP()

    def connect(self) -> None:
        """ Connect to FTP socket.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.client.connect(self.host, self.port, timeout=self.timeout)
        except Exception:
            raise RuntimeError(f"Connection failed for {self.pair}!")

    def close(self) -> None:
        """ Close FTP socket.

        :return None: None
        :raise RuntimeError: with trailing error message
        """

        try:
            self.client.close()
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

    def login(self, username: str, password: str) -> None:
        """ Login to the FTP socket.

        :param str username: FTP username
        :param str password: FTP password
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.client.login(username, password)
        except Exception:
            raise RuntimeError(f"Authentication via {self.username}:{self.password} failed for {self.pair}!")

    def get_file(self, remote_file: str) -> bytes:
        """ Get remote file from FTP socket.

        :param str remote_file: remote file to get
        :return bytes: remote file contents
        """

        try:
            fp_content = io.BytesIO()
            self.client.retrbinary(f"RETR {remote_file}", fp_content.write)
            return fp_content.getvalue()
        except Exception:
            return b""
