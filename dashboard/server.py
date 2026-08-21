"""
MailFlow SME Admin Dashboard Server
Lightweight HTTP static file server bound to 0.0.0.0:8500.
"""

import http.server
import socketserver
import os
import sys

PORT = 8500
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


class DashboardHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # Enable CORS and caching headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def log_message(self, format, *args):
        # Clean formatted request logger
        if len(args) >= 2:
            sys.stderr.write(f"[MailFlow Dashboard :8500] {args[0]} - {args[1]}\n")


def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), DashboardHTTPRequestHandler) as httpd:
        print("=" * 60)
        print("  MailFlow Fleet Command — SME Admin Dashboard")
        print(f"  Local Access:    http://127.0.0.1:{PORT}")
        print(f"  LAN Access:      http://0.0.0.0:{PORT}")
        print(f"  Serving Directory: {DIRECTORY}")
        print("  Press [Ctrl+C] to stop server cleanly")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server...")
            httpd.server_close()


if __name__ == "__main__":
    run()
