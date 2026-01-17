#!/usr/bin/env python3
"""
Receiver Client - Connects to SGX server and requests aggregated data
"""

import socket
import ssl
import sys
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

ALLOW_SIM_MODE = True
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

def receiver_client():
    print("=== PSI_SGX Receiver Client ===")
    print(f"Connecting to SGX server at {SERVER_HOST}:{SERVER_PORT}")
    
    # Create SSL context (allow self-signed certs for SIM mode)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE if ALLOW_SIM_MODE else ssl.CERT_REQUIRED
    
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            print("[RECEIVER] TLS handshake completed!")
            print(f"[RECEIVER] Cipher: {ssock.cipher()}")
            
            if ALLOW_SIM_MODE:
                print("[RECEIVER] WARNING: Running in SIM mode - server quote not verified!")
            
            # Send identification
            ident = b"RECEIVER\n"
            ssock.sendall(ident)
            print("[RECEIVER] Sent identification")
            
            # ============= ECDH Key Exchange =============
            
            # 1. Receive server's ECDH public key (64 bytes)
            print("[RECEIVER] Receiving server ECDH public key...")
            server_pubkey_bytes = ssock.recv(64)
            if len(server_pubkey_bytes) != 64:
                print(f"[RECEIVER] ERROR: Expected 64 bytes, got {len(server_pubkey_bytes)}")
                return None
            print(f"[RECEIVER] Received server pubkey: {len(server_pubkey_bytes)} bytes")
            
            # 2. Generate client ECDH keypair (P-256)
            print("[RECEIVER] Generating client ECDH keypair...")
            client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            client_public_key = client_private_key.public_key()
            
            # Extract public key bytes (x || y, 32 bytes each, total 64 bytes)
            public_numbers = client_public_key.public_numbers()
            client_pubkey_bytes = public_numbers.x.to_bytes(32, byteorder='big') + \
                                   public_numbers.y.to_bytes(32, byteorder='big')
            print(f"[RECEIVER] Generated client pubkey: {len(client_pubkey_bytes)} bytes")
            
            # 3. Send client public key to server
            ssock.sendall(client_pubkey_bytes)
            print("[RECEIVER] Sent client pubkey to server")
            
            # 4. Derive shared secret (try little-endian for SGX)
            try:
                server_x_int = int.from_bytes(server_pubkey_bytes[:32], byteorder='little')
                server_y_int = int.from_bytes(server_pubkey_bytes[32:], byteorder='little')
                server_public_numbers = ec.EllipticCurvePublicNumbers(
                    x=server_x_int,
                    y=server_y_int,
                    curve=ec.SECP256R1()
                )
                server_public_key_obj = server_public_numbers.public_key(default_backend())
                shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key_obj)
                print(f"[RECEIVER] ECDH succeeded with little-endian")
            except ValueError:
                print("[RECEIVER] ERROR: ECDH failed")
                return None
            
            print(f"[RECEIVER] Shared secret derived: {len(shared_secret)} bytes")
            
            # 5. Derive AES key (SGX uses little-endian shared secret)
            shared_secret_le = shared_secret[::-1]
            key_material = hashlib.sha256(shared_secret_le).digest()
            aes_key = key_material[:16]
            
            print(f"[RECEIVER] AES key derived: {aes_key.hex()}")
            
            # ============= Request Loop =============
            
            while True:
                cmd = input("\n[RECEIVER] Enter command (FETCH/QUIT): ").strip().upper()
                
                if cmd == 'QUIT':
                    ssock.sendall(b'Q')
                    print("[RECEIVER] Sent QUIT, closing connection...")
                    break
                
                if cmd == 'FETCH':
                    # Send FETCH command
                    ssock.sendall(b'F')
                    print("[RECEIVER] Sent FETCH request...")
                    
                    # Receive encrypted response: [IV:12][size:4][encrypted_data][tag:16]
                    
                    # Receive IV
                    result_iv = b''
                    while len(result_iv) < 12:
                        chunk = ssock.recv(12 - len(result_iv))
                        if not chunk:
                            print("[RECEIVER] ERROR: Connection closed while receiving IV")
                            return None
                        result_iv += chunk
                    print(f"[RECEIVER] Received IV: {len(result_iv)} bytes")
                    
                    # Receive size (actual data size in bytes)
                    result_size_bytes = b''
                    while len(result_size_bytes) < 4:
                        chunk = ssock.recv(4 - len(result_size_bytes))
                        if not chunk:
                            print("[RECEIVER] ERROR: Connection closed while receiving size")
                            return None
                        result_size_bytes += chunk
                    actual_size = struct.unpack('I', result_size_bytes)[0]
                    
                    # Calculate encrypted size (padded to 4-byte boundary)
                    encrypted_size = ((actual_size + 3) // 4) * 4
                    print(f"[RECEIVER] Receiving {actual_size} bytes (encrypted: {encrypted_size} bytes)...")
                    
                    # Receive encrypted data
                    encrypted_result = b''
                    while len(encrypted_result) < encrypted_size:
                        chunk = ssock.recv(encrypted_size - len(encrypted_result))
                        if not chunk:
                            print("[RECEIVER] ERROR: Connection closed prematurely")
                            return None
                        encrypted_result += chunk
                    print(f"[RECEIVER] Received encrypted data: {len(encrypted_result)} bytes")
                    
                    # Receive GCM tag
                    result_tag = b''
                    while len(result_tag) < 16:
                        chunk = ssock.recv(16 - len(result_tag))
                        if not chunk:
                            print("[RECEIVER] ERROR: Connection closed while receiving tag")
                            return None
                        result_tag += chunk
                    print(f"[RECEIVER] Received GCM tag: {len(result_tag)} bytes")
                    
                    # Decrypt
                    ciphertext_with_tag = encrypted_result + result_tag
                    cipher = AESGCM(aes_key)
                    
                    try:
                        plaintext_result = cipher.decrypt(result_iv, ciphertext_with_tag, None)
                        # Extract actual data (unpad)
                        actual_data = plaintext_result[:actual_size]
                        print(f"\n[RECEIVER] ===== DECRYPTED RESPONSE =====")
                        print(actual_data.decode('utf-8', errors='replace'))
                        print(f"[RECEIVER] ==============================\n")
                    except Exception as e:
                        print(f"[RECEIVER] ERROR: Decryption failed: {e}")
                
                else:
                    print("[RECEIVER] Unknown command. Use FETCH or QUIT.")

if __name__ == '__main__':
    try:
        receiver_client()
    except KeyboardInterrupt:
        print("\n[RECEIVER] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"[RECEIVER] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
