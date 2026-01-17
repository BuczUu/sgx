# SGX PSI (Private Set Intersection) System - Build & Run Guide

## Overview

This is a secure data aggregation system using Intel SGX (Software Guard Extensions) with the following architecture:

- **SGX Enclave** (`Enclave/`): Trusted computation environment that aggregates encrypted data
- **Server** (`Server_RATLS.cpp`): TLS endpoint that accepts data servers and receivers
- **Data Servers** (`data_server.py`): Multiple clients that connect to SGX and provide encrypted data
- **Receiver Client** (`receiver_client.py`): Client that queries aggregated data with end-to-end encryption

## Security Architecture

```
┌─────────────────┐         TLS over TCP          ┌──────────────┐
│  Data Server 1  ├─────────────────────────────┐ │              │
└─────────────────┘                             │ │              │
                                                ├──┤  SGX Server ├── Length-prefixed
┌─────────────────┐         TLS over TCP        │ │              │    protocol
│  Data Server 2  ├─────────────────────────────┤ │  (Server_    │    (send/recv)
└─────────────────┘                             │ │   RATLS)     │
                                                │ │              │
┌──────────────────┐    TLS + ECDH + AES-GCM  │ │              │
│ Receiver Client  ├────────────────────────────┤ │              │
└──────────────────┘                             └──┬───────────┬┘
                                                    │           │
                                                    │ OCALL     │
                                                    │ send/recv │
                                                    │           │
                                                 ┌──┴───────────┴──┐
                                                 │   SGX Enclave   │
                                                 │  (Enclave.cpp)  │
                                                 │                 │
                                                 │ - Aggregates    │
                                                 │   data from     │
                                                 │   all servers   │
                                                 │ - Encrypts      │
                                                 │   result with   │
                                                 │   AES-GCM       │
                                                 └─────────────────┘
```

## Build Prerequisites

- **Intel SGX SDK**: Installed at `/opt/intel/sgxsdk` (SIM mode)
- **mbedTLS**: Included in SGX SDK
- **Python 3.8+**: For data_server.py and receiver_client.py
- **cryptography library**: `pip install cryptography`

## Build Instructions

```bash
cd /home/marcel/sgx_lab/examples/PSI_SGX
make clean && make
```

The build system will:
1. Run edger8r to generate SGX marshaling code (Enclave_u.{c,h}, Enclave_t.{c,h})
2. Compile the trusted enclave code (Enclave.cpp)
3. Link the enclave and sign it (enclave.signed.so)
4. Compile the untrusted server (Server_RATLS.cpp)
5. Generate test keys if needed

**Output binaries:**
- `server` - Main TLS/OCALL server (executable)
- `enclave.signed.so` - Signed SGX enclave (2.9 MB)
- `Enclave_u.c/h` - SGX untrusted stubs for enclave calls
- Python scripts: `data_server.py`, `receiver_client.py`

## Running the System

### Prerequisites for Runtime

The SGX runtime libraries must be available (not needed for build-only):
```bash
export LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64:/path/to/sample_libcrypto:$LD_LIBRARY_PATH
```

### 1. Start the Server

```bash
cd /home/marcel/sgx_lab/examples/PSI_SGX
./server
```

**Expected output:**
```
[SERVER] Starting SGX enclave...
[SERVER] Loading enclave 'enclave.signed.so'
[SERVER] Listening on 0.0.0.0:12345
```

### 2. Connect Data Servers (in separate terminals)

```bash
# Terminal 2
python3 data_server.py --server-id 1 --payload "Server1_Data: [payload1]"

# Terminal 3
python3 data_server.py --server-id 2 --payload "Server2_Data: [payload2]"
```

**Expected output:**
```
[DATA_SERVER 1] Connecting to SGX at 127.0.0.1:12345 (TLS)
[DATA_SERVER 1] TLS handshake OK
[DATA_SERVER 1] Sent ID
```

Each data server will:
1. Establish TLS connection to port 12345
2. Send identification: `SERVER:1\n` and `SERVER:2\n`
3. Register in SGX's client map (OCALL from enclave)
4. Enter request-response loop (wait for aggregation query)

### 3. Query with Receiver Client

```bash
# Terminal 4
python3 receiver_client.py
```

**Expected output:**
```
[RECEIVER] Connecting to SGX at 127.0.0.1:12345
[RECEIVER] TLS handshake OK
[RECEIVER] Sent identification: RECEIVER
[RECEIVER] Starting ECDH key exchange...
[RECEIVER] Sent ECDH pubkey (65 bytes)
[RECEIVER] Received server ECDH pubkey (65 bytes)
[RECEIVER] ECDH completed, shared secret: 32 bytes
[RECEIVER] Derived AES-128-GCM key: a1b2c3d4...
[RECEIVER] Sent FETCH command
[RECEIVER] Received IV: 16 random bytes
[RECEIVER] Received encrypted data: XXX bytes
[RECEIVER] Decryption successful!
[RECEIVER] PSI Result (XXX bytes):
Server1_Data: [payload1]
Server2_Data: [payload2]
```

## Communication Protocols

### Data Server ↔ SGX Server (TLS + Length-Prefixed)

1. **Identification** (plaintext after TLS):
   ```
   SERVER:<id>\n
   ```
   
2. **Data Exchange** (length-prefixed binary):
   ```
   [4-byte size in little-endian] [payload]
   ```

### Receiver Client ↔ SGX Server (TLS + ECDH + AES-GCM)

1. **Identification** (plaintext after TLS):
   ```
   RECEIVER\n
   ```

2. **ECDH Key Exchange**:
   ```
   Client sends: [2-byte length] [65-byte uncompressed P-256 public key]
   Server responds: [2-byte length] [65-byte uncompressed P-256 public key]
   Both derive shared secret = ECDH(client_private, server_public)
   KDF: SHA256-based HKDF with salt="SGX_PSI_KEY", info="AES128GCM"
   Result: 128-bit AES key
   ```

3. **Data Request** (encrypted with AES-128-GCM):
   ```
   Client sends: b"F" (FETCH command, unencrypted over TLS)
   Server responds: [16-byte IV] [encrypted aggregated result] [16-byte GCM tag]
   ```

## Code Structure

### Server_RATLS.cpp
- **Main entry**: `main()` - loads enclave, listens on port 12345, spawns threads
- **Key function**: `client_handler()` - reads client ID, branches to ECDH (receiver) or OCALL (server)
- **OCALL handlers**: `ocall_send_encrypted()`, `ocall_recv_encrypted()` - communicate with data servers
- **Enclave interface**: Links against `Enclave_u.{c,h}` (auto-generated by edger8r)

### Enclave/Enclave.cpp
- **ECALL**: `ecall_receiver_request()` - aggregates data from all registered servers
  - Loops through g_clients map (populated by OCALL during data server connection)
  - Sends length-prefixed queries via OCALL
  - Concatenates responses with separator
  - Encrypts result with AES-128-GCM using provided key
- **Crypto**: Uses mbedTLS inside enclave for AES-GCM, ECDH (P-256)

### Enclave/Enclave.edl (EDL Contract)
Defines ECALL/OCALL interface:
- `ecall_receiver_request` - enclave function called from untrusted server
- `ocall_send_encrypted` - untrusted function to send data to servers
- `ocall_recv_encrypted` - untrusted function to receive data from servers

### data_server.py
- Connects to SGX server via TLS
- Sends identification (`SERVER:id\n`)
- Loops reading [length][payload] requests and responding with same format
- Simulates data source (stores fixed payload)

### receiver_client.py
- Connects to SGX server via TLS
- Sends identification (`RECEIVER\n`)
- Performs ECDH key exchange (P-256)
- Derives AES-128-GCM key using HKDF
- Sends FETCH command
- Receives IV + ciphertext + tag
- Decrypts and displays aggregated result

## Makefile Targets

```bash
make                 # Build everything (default)
make clean           # Remove all build artifacts and binaries
make clean && make   # Full rebuild
```

**Variables:**
- `SGX_MODE=SIM` - Simulation mode (default)
- `SGX_DEBUG=1` - Debug symbols (default)
- `SGX_MODE=HW` - Hardware mode (requires SGX-enabled CPU)

## Troubleshooting

### Build Fails: "No rule to make target 'EnclaveClient/EnclaveClient.edl'"
**Solution**: EnclaveClient is legacy code. It's been removed from the Makefile. Run `make clean && make`.

### Runtime: "error while loading shared libraries: libsgx_urts_sim.so"
**Solution**: SGX runtime not installed. Install SGX SDK or set `LD_LIBRARY_PATH` to SGX lib directory.

### Data servers don't connect
**Check server is listening:**
```bash
netstat -tulpn | grep 12345
```
**Verify client certificate handling (demo mode skips verification)** - see Server_RATLS.cpp line ~100

### Receiver client gets empty result
**Check data servers are connected:**
- Server console should show "CLIENT connected" messages
- g_clients map in enclave should be non-empty
- Check ocall_send_encrypted is being called

### ECDH fails with "Invalid public key format"
**Verify P-256 uncompressed point format** (65 bytes: 0x04 + 32-byte X + 32-byte Y)
- Check receiver_client.py line ~60 sends correct format
- Check Server_RATLS.cpp line ~350 receives and parses correctly

## Production Considerations

1. **Certificate Management**: Replace trust-all SSL with proper CA certificates
2. **Key Material**: Generate enclave signing keys and protect them
3. **Hardware SGX**: Test with SGX-enabled CPU (HW mode) not just simulation
4. **Attestation**: Add remote attestation to verify enclave authenticity
5. **Data Validation**: Validate all inputs in enclave before processing
6. **Cleanup**: Securely erase sensitive data after decryption (use memset_s)
7. **Logging**: Remove debug printf calls in production
8. **Performance**: Tune enclave heap/stack sizes (Enclave.config.xml)

## Files Removed (Legacy Code)

The following files were removed as they're unused:
- `EnclaveClient/` - Legacy enclave for client-side operations
- `Client.cpp` - Old untrusted app, replaced by receiver_client.py
- `client_python.py` - Outdated receiver implementation
- `client_go.go` - Old Go client (unused)
- Build outputs: `enclave.so`, `*.o` files, generated stubs

## Performance Notes

- **Enclave Signing**: ~5 seconds (one-time during build)
- **TLS Handshake**: ~200ms per connection (full handshake)
- **Data Aggregation**: Linear in number of data servers + payload size
- **AES-GCM**: Hardware-accelerated if available
- **ECDH P-256**: ~10ms using hardware elliptic curve operations

## References

- SGX SDK Documentation: `/opt/intel/sgxsdk/docs/`
- mbedTLS: `https://github.com/ARMmbed/mbedtls`
- ECDH/AES-GCM in cryptography library: `https://cryptography.io/`
- Intel SGX Explained: Intel whitepaper (2016)
