#!/usr/bin/env python3
"""
Data Server 1 - Simple TCP server that returns static data
Port: 9001
"""

import socket
import sys

HOST = '127.0.0.1'
PORT = 9001
DATA = "Server1_Data: [Temperature=25C, Humidity=60%]"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[SERVER 1] Listening on {HOST}:{PORT}")
        print(f"[SERVER 1] Will return: {DATA}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[SERVER 1] Connection from {addr}")
                
                # Read request
                request = conn.recv(1024).decode('utf-8').strip()
                print(f"[SERVER 1] Request: {request}")
                
                # Send response
                conn.sendall(DATA.encode('utf-8'))
                print(f"[SERVER 1] Sent {len(DATA)} bytes")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SERVER 1] Shutting down...")
        sys.exit(0)
