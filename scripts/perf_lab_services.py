"""Fikcyjne usługi dla laboratorium testu skali: HTTP (panel, staging), baner SSH."""

from __future__ import annotations

import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler

PAGES = [
    ("Strona główna", {}),
    ("Panel logowania - staging", {"X-Powered-By": "PHP/8.1"}),
    ("Grafana", {"Server": "nginx/1.25.3"}),
]


def http_handler(index: int) -> type[BaseHTTPRequestHandler]:
    title, extra = PAGES[index % len(PAGES)]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            code = 200 if self.path in ("/", "/login", "/admin") or index % 3 else 404
            body = f"<html><head><title>{title}</title></head><body>demo</body></html>".encode()
            self.send_response(code)
            for key, value in extra.items():
                self.send_header(key, value)
            self.send_header("Set-Cookie", "PHPSESSID=demo; Path=/")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    return Handler


class Ssh(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")


def serve(server: socketserver.BaseServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main(path: str) -> None:
    socketserver.TCPServer.allow_reuse_address = True
    for index, ip in enumerate(open(path).read().split()):
        serve(socketserver.ThreadingTCPServer((ip, 22), Ssh))
        if index % 2 == 0:
            from http.server import ThreadingHTTPServer

            port = 8080 if index % 4 == 0 else 80
            serve(ThreadingHTTPServer((ip, port), http_handler(index)))
    threading.Event().wait()


if __name__ == "__main__":
    main(sys.argv[1])
