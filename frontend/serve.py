#!/usr/bin/env python3
"""
Simple HTTP server for Secure Lens AI frontend
Serves the standalone HTML frontend on port 3000
"""

import http.server
import socketserver
import os
import mimetypes

PORT = 3000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# Register video MIME types
mimetypes.add_type('video/mp4', '.mp4')
mimetypes.add_type('video/webm', '.webm')

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # required for video streaming / range requests

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # Enable CORS
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        # Don't cache-bust static assets like video
        if not self.path.endswith(('.mp4', '.webm', '.png', '.jpg', '.js', '.css')):
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_GET(self):
        # Route / to index.html (home page)
        if self.path == '/':
            self.path = '/index.html'
        # Route known pages
        elif self.path in ('/home', '/login', '/analysis', '/contact', '/account'):
            self.path = f'{self.path}.html'
        # Handle Range requests for video streaming
        if self.path.endswith('.mp4'):
            return self._serve_video()
        return super().do_GET()

    def _serve_video(self):
        """Serve video with Range request support."""
        path = self.translate_path(self.path)
        if not os.path.isfile(path):
            self.send_error(404)
            return
        file_size = os.path.getsize(path)
        range_header = self.headers.get('Range')
        if range_header:
            # Parse Range: bytes=start-end
            range_spec = range_header.replace('bytes=', '')
            parts = range_spec.split('-')
            start = int(parts[0]) if parts[0] else 0
            end = int(parts[1]) if len(parts) > 1 and parts[1] else file_size - 1
            end = min(end, file_size - 1)
            chunk_size = end - start + 1
            self.send_response(206)
            self.send_header('Content-Type', 'video/mp4')
            self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
            self.send_header('Content-Length', str(chunk_size))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers()
            with open(path, 'rb') as f:
                f.seek(start)
                self.wfile.write(f.read(chunk_size))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'video/mp4')
            self.send_header('Content-Length', str(file_size))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers()
            with open(path, 'rb') as f:
                self.wfile.write(f.read())

    def do_HEAD(self):
        """Handle HEAD requests — needed so browsers see Accept-Ranges before sending Range GET."""
        if self.path.endswith('.mp4'):
            path = self.translate_path(self.path)
            if os.path.isfile(path):
                file_size = os.path.getsize(path)
                self.send_response(200)
                self.send_header('Content-Type', 'video/mp4')
                self.send_header('Content-Length', str(file_size))
                self.send_header('Accept-Ranges', 'bytes')
                self.end_headers()
                return
        return super().do_HEAD()

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

print("=" * 50)
print("Secure Lens AI Frontend Server")
print("=" * 50)
print(f"Starting server on http://localhost:{PORT}")
print(f"Serving files from: {DIRECTORY}")
print("\nOpen your browser to: http://localhost:3000")
print("Press Ctrl+C to stop")
print("=" * 50)

with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nServer stopped.")
