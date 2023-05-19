package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

/*
	generate rsa key
	- openssl genrsa -out private.key 4096

*/

func getRSAKeyFromFile(fileName string) (*rsa.PrivateKey, error) {
	file, err := os.ReadFile(fileName)
	if err != nil {
		return &rsa.PrivateKey{}, err
	}
	senderPrivateKey, err := getRSAKey(string(file))
	if err != nil {
		return &rsa.PrivateKey{}, err
	}

	return senderPrivateKey, nil
}

func getRSAKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return &rsa.PrivateKey{}, err
	}

	return key, nil
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s", err)
	}
	return privateKey, nil
}

func exportPublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return publicKeyPEM, nil
}

func importPublicKey(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %s", err)
	}
	return publicKey, nil
}

func encryptMessage(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return nil, fmt.Errorf("encryption error: %s", err)
	}
	return ciphertext, nil
}

func decryptMessage(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %s", err)
	}
	return plaintext, nil
}

func main() {
	// Generate a key pair for the sender
	// senderPrivateKey, err := generateKeyPair()
	// if err != nil {
	// 	fmt.Printf("Failed to generate sender's private key: %s\n", err)
	// 	return
	// }

	// senderPrivateKey, err := getRSAKey(RSAKey)
	// if err != nil {
	// 	fmt.Printf("Failed to generate sender's private key: %s\n", err)
	// 	return
	// }

	receiverPrivateKey, err := getRSAKeyFromFile("./private.key")
	if err != nil {
		fmt.Printf("Failed to generate sender's private key: %s\n", err)
		return
	}

	// Export the sender's public key
	receiverPublicKeyPEM, err := exportPublicKey(&receiverPrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to export sender's public key: %s\n", err)
		return
	}

	fmt.Printf("receiver public key:%s", string(receiverPublicKeyPEM))

	// Simulate sending the public key to the receiver (e.g., over a network)

	// Import the receiver's public key (received from the sender)
	senderEncryptorKey, err := importPublicKey(receiverPublicKeyPEM)
	if err != nil {
		fmt.Printf("Failed to import receiver's public key: %s\n", err)
		return
	}

	// Encrypt a message using the receiver's public key
	message := []byte("Hello, receiver!")
	encryptedMessage, err := encryptMessage(message, senderEncryptorKey)
	if err != nil {
		fmt.Printf("Failed to encrypt message: %s\n", err)
		return
	}

	// Decrypt the ciphertext using the receiver's private key
	plaintext, err := decryptMessage(encryptedMessage, receiverPrivateKey)
	if err != nil {
		fmt.Printf("Failed to decrypt message: %s\n", err)
		return
	}

	fmt.Printf("Decrypted message: %s\n", plaintext)
}

var RSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`
