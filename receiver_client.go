package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"syscall"
)

const (
	SGX_HOST = "127.0.0.1"
	SGX_PORT = "12345"
)

// DeriveAESKey - derive AES key from shared secret (SHA256, first 16 bytes)
// Matches Enclave behavior: sgx_sha256_msg on shared secret
func DeriveAESKey(sharedSecret []byte) []byte {
	hash := sha256.Sum256(sharedSecret)
	return hash[:16]
}

// reverseBytes - reverse a byte slice
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// P256PointToBytes - convert point to 64-byte format (big-endian)
func P256PointToBytes(x, y *big.Int) []byte {
	result := make([]byte, 64)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(result[32-len(xBytes):32], xBytes)
	copy(result[64-len(yBytes):64], yBytes)
	return result
}

// BytesToP256Point - convert 64-byte format to point (try both endianness)
func BytesToP256Point(data []byte) (*big.Int, *big.Int, error) {
	if len(data) != 64 {
		return nil, nil, fmt.Errorf("invalid P256 point format (expected 64 bytes, got %d)", len(data))
	}

	curve := elliptic.P256()

	// Try little-endian first
	x := new(big.Int).SetBytes(reverseBytes(data[0:32]))
	y := new(big.Int).SetBytes(reverseBytes(data[32:64]))

	if curve.IsOnCurve(x, y) {
		return x, y, nil
	}

	// Try big-endian
	x = new(big.Int).SetBytes(data[0:32])
	y = new(big.Int).SetBytes(data[32:64])

	if curve.IsOnCurve(x, y) {
		return x, y, nil
	}

	return nil, nil, fmt.Errorf("point not on P256 curve (tried both endianness)")
}

// PerformECDH - ECDH key exchange
func PerformECDH(conn *tls.Conn) ([]byte, error) {
	fmt.Println("[RECEIVER] Starting ECDH key exchange...")

	curve := elliptic.P256()

	clientPrivate, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	clientX, clientY := curve.ScalarBaseMult(clientPrivate.Bytes())
	clientPubkey := P256PointToBytes(clientX, clientY)

	// Receive server pubkey first
	serverPubkey := make([]byte, 64)
	if _, err := io.ReadFull(conn, serverPubkey); err != nil {
		return nil, fmt.Errorf("failed to receive server pubkey: %v", err)
	}
	fmt.Printf("[RECEIVER] Received server ECDH pubkey (%d bytes)\n", len(serverPubkey))

	// Parse server pubkey
	serverX, serverY, err := BytesToP256Point(serverPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid server pubkey: %v", err)
	}

	// Send client pubkey
	if _, err := conn.Write(clientPubkey); err != nil {
		return nil, fmt.Errorf("failed to send client pubkey: %v", err)
	}
	fmt.Printf("[RECEIVER] Sent ECDH pubkey (%d bytes)\n", len(clientPubkey))

	// Compute shared secret
	sharedX, _ := curve.ScalarMult(serverX, serverY, clientPrivate.Bytes())
	sharedSecret := sharedX.Bytes()

	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	// Debug: print shared secret
	fmt.Printf("[RECEIVER] Shared secret (BE): %x\n", sharedSecret)

	// SGX stores shared secret in little-endian, reverse it
	sharedSecret = reverseBytes(sharedSecret)
	fmt.Printf("[RECEIVER] Shared secret (LE): %x\n", sharedSecret)

	fmt.Printf("[RECEIVER] ECDH completed, shared secret: %d bytes\n", len(sharedSecret))
	return sharedSecret, nil
}

// RunReceiver - main receiver logic
func RunReceiver(host, port string) error {
	addr := host + ":" + port
	fmt.Printf("[RECEIVER] Connecting to SGX at %s\n", addr)

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	fmt.Println("[RECEIVER] TLS handshake OK")

	if _, err := conn.Write([]byte("RECEIVER\n")); err != nil {
		return fmt.Errorf("failed to send identification: %v", err)
	}
	fmt.Println("[RECEIVER] Sent identification: RECEIVER")

	sharedSecret, err := PerformECDH(conn)
	if err != nil {
		return fmt.Errorf("ECDH failed: %v", err)
	}

	key := DeriveAESKey(sharedSecret)
	fmt.Printf("[RECEIVER] Derived AES-128-GCM key: %s\n", hex.EncodeToString(key))

	// Interactive loop for commands
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("[RECEIVER] Ready. Type 'F' to FETCH data, 'Q' to QUIT")

	for {
		fmt.Print("Enter command (F/Q): ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()

		if len(command) == 0 {
			continue
		}

		cmd := command[0]
		if cmd == 'Q' || cmd == 'q' {
			fmt.Println("[RECEIVER] Quitting...")
			if _, err := conn.Write([]byte("Q")); err != nil {
				fmt.Printf("[RECEIVER] Failed to send QUIT: %v\n", err)
			}
			break
		}

		if cmd == 'F' || cmd == 'f' {
			if _, err := conn.Write([]byte("F")); err != nil {
				return fmt.Errorf("failed to send FETCH command: %v", err)
			}
			fmt.Println("[RECEIVER] Sent FETCH command")

			// Receive: [IV:12][size:4][encrypted_data][tag:16]
			iv := make([]byte, 12)
			if _, err := io.ReadFull(conn, iv); err != nil {
				return fmt.Errorf("failed to receive IV: %v", err)
			}
			fmt.Printf("[RECEIVER] Received IV: %s\n", hex.EncodeToString(iv))

			// Read size (4 bytes, little-endian)
			sizeBytes := make([]byte, 4)
			if _, err := io.ReadFull(conn, sizeBytes); err != nil {
				return fmt.Errorf("failed to receive data size: %v", err)
			}
			dataSize := uint32(sizeBytes[0]) | uint32(sizeBytes[1])<<8 | uint32(sizeBytes[2])<<16 | uint32(sizeBytes[3])<<24
			fmt.Printf("[RECEIVER] Data size: %d bytes\n", dataSize)

			// Read encrypted data (aligned to 4-byte chunks)
			encryptedDataSize := ((dataSize + 3) / 4) * 4
			encryptedData := make([]byte, encryptedDataSize)
			if _, err := io.ReadFull(conn, encryptedData); err != nil {
				return fmt.Errorf("failed to receive encrypted data: %v", err)
			}
			fmt.Printf("[RECEIVER] Received encrypted data: %d bytes\n", encryptedDataSize)

			// Read tag (16 bytes)
			tag := make([]byte, 16)
			if _, err := io.ReadFull(conn, tag); err != nil {
				return fmt.Errorf("failed to receive GCM tag: %v", err)
			}
			fmt.Printf("[RECEIVER] Received GCM tag: %s\n", hex.EncodeToString(tag))

			// Decrypt ALL encrypted data (including padding), then trim to actual size
			fmt.Printf("[RECEIVER] Decrypting %d bytes (will trim to %d)\n", encryptedDataSize, dataSize)

			block, err := aes.NewCipher(key)
			if err != nil {
				return fmt.Errorf("failed to create AES cipher: %v", err)
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return fmt.Errorf("failed to create GCM: %v", err)
			}

			// Decrypt with full encrypted data + tag
			ciphertextWithTag := append(encryptedData, tag...)

			plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
			if err != nil {
				return fmt.Errorf("decryption failed: %v", err)
			}

			// Trim to actual data size (remove padding)
			plaintext = plaintext[:dataSize]

			fmt.Println("[RECEIVER] ✓ Decryption successful!")
			fmt.Printf("[RECEIVER] PSI Result (%d bytes):\n", len(plaintext))
			fmt.Println(string(plaintext))
			fmt.Println()
		} else {
			fmt.Println("[RECEIVER] Unknown command. Use 'F' for FETCH or 'Q' to QUIT")
		}
	}

	return nil
}

func main() {
	host := SGX_HOST
	port := SGX_PORT

	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	fmt.Println("=== PSI_SGX Receiver Client (Go) ===")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[RECEIVER] Shutting down...")
		os.Exit(0)
	}()

	if err := RunReceiver(host, port); err != nil {
		fmt.Printf("[RECEIVER] ERROR: %v\n", err)
		os.Exit(1)
	}
}
