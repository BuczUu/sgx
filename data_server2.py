#!/usr/bin/env python3
"""
Data Server 2 - Simple TCP server that returns static data
Port: 9002
"""

import socket
import sys

HOST = '127.0.0.1'
PORT = 9002
DATA = "Server2_Data: [Pressure=1013hPa, Wind=15km/h]"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[SERVER 2] Listening on {HOST}:{PORT}")
        print(f"[SERVER 2] Will return: {DATA}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[SERVER 2] Connection from {addr}")
                
                # Read request
                request = conn.recv(1024).decode('utf-8').strip()
                print(f"[SERVER 2] Request: {request}")
                
                # Send response
                conn.sendall(DATA.encode('utf-8'))
                print(f"[SERVER 2] Sent {len(DATA)} bytes")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SERVER 2] Shutting down...")
        sys.exit(0)
