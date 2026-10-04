"""Airlock egress proxy: the sandbox's only route out.

- Plain HTTP requests are reverse-proxied to api.anthropic.com with the real API key injected,
  so the key never exists inside the agent's container.
- CONNECT tunnels (HTTPS_PROXY) are allowed only to hosts in AIRLOCK_ALLOW_HOSTS (default: none).
"""
import http.client
import http.server
import os
import select
import socket

UPSTREAM = "api.anthropic.com"
KEY = os.environ.pop("ANTHROPIC_API_KEY")
ALLOW = {h for h in os.environ.get("AIRLOCK_ALLOW_HOSTS", "").split(",") if h}
DROP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "transfer-encoding", "te",
        "trailer", "upgrade", "host", "content-length", "x-api-key", "authorization"}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(":")
        if host not in ALLOW or port != "443":
            self.send_error(403, f"airlock: egress to {self.path} denied")
            return
        try:
            up = socket.create_connection((host, 443), timeout=30)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200)
        self.end_headers()
        pair = {self.connection: up, up: self.connection}
        with up:
            while True:
                ready, _, _ = select.select(list(pair), [], [], 300)
                if not ready:
                    return
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        return
                    pair[s].sendall(data)
        self.close_connection = True

    def forward(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP}
        headers["x-api-key"] = KEY
        conn = http.client.HTTPSConnection(UPSTREAM, timeout=600)
        try:
            conn.request(self.command, self.path, body, headers)
            resp = conn.getresponse()
        except OSError:
            self.send_error(502)
            return
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in DROP:
                self.send_header(k, v)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        while chunk := resp.read1(65536):  # stream, so SSE responses arrive as they're generated
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        conn.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = forward


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("ready", flush=True)
    server.serve_forever()
