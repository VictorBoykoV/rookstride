#!/usr/bin/env python3
"""Serve only the public static site on this computer's loopback interface."""
import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DIST=Path(__file__).resolve().parents[1]/'dist'
CSP="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'none'"

class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Content-Security-Policy',CSP)
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
        self.send_header('Cache-Control','no-cache')
        super().end_headers()
    def list_directory(self,path):
        self.send_error(404)
        return None
    def send_error(self,code,message=None,explain=None):
        if code==404 and (DIST/'404.html').exists():
            body=(DIST/'404.html').read_bytes()
            self.send_response(404)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            if self.command!='HEAD': self.wfile.write(body)
        else:
            super().send_error(code,message,explain)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--no-js',action='store_true',help='Test the static fallback with scripts blocked by CSP.')
    args=parser.parse_args()
    if args.no_js: CSP=CSP.replace("script-src 'self'","script-src 'none'")
    if not (DIST/'index.html').exists(): parser.error('Run scripts/build.py first.')
    server=ThreadingHTTPServer(('127.0.0.1',args.port),functools.partial(Handler,directory=str(DIST)))
    print(f'Rookstride local preview: http://127.0.0.1:{args.port}/',flush=True)
    print('Serving only website/dist; press Ctrl+C to stop.',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
