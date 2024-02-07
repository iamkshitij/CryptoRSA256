package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {

	id := "983522"
	// handshake to get public key
	publicKey := handShake(id)
	fmt.Println("Public Key: \n" + publicKey)

	// get 32bit secret key
	secretKey, _ := getSecretKey()
	fmt.Println("Secret Key: ", secretKey)

	// convert string public key to *rsa.PublicKey
	pubKey := getPublicKeyFromStr(publicKey)

	// RSA-256 encryption of secret key
	eCTByte := rsa256Enc(pubKey, []byte(secretKey))

	//  base64 encoding of rsa 256 encrypted key
	val := base64.StdEncoding.EncodeToString(eCTByte)
	fmt.Printf("%s", val)

	// decoding the encrypted key
	b64Decoded, _ := base64.StdEncoding.DecodeString(val)

	// read private key based on id
	bPk, _ := os.ReadFile(id + "_private_key.pem")

	// convert pem to *rsa.PrivateKey
	privateKey, _ := pemToRSAPrivateKey(bPk)

	// decrypt secret key using rsa 256 method
	op, _ := rsa256Dec(privateKey, b64Decoded)
	fmt.Println()
	fmt.Println("Decrypted Secret Key")

	// print the secret key
	fmt.Printf("%s", op)

}

func rsa256Dec(privKey *rsa.PrivateKey, str []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privKey, str)
}

func pemToRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

func getSecretKey() (string, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(key), nil
}

func getPublicKeyFromStr(sr string) *rsa.PublicKey {
	blockBytes, _ := base64.StdEncoding.DecodeString(sr)
	blocks := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: blockBytes,
	}

	pubKeyInterface, err := x509.ParsePKCS1PublicKey(blocks.Bytes)
	if err != nil {
		fmt.Errorf("failed to parse public key: %v", err)
	}

	//	fmt.Println("Content without Pem file: \n", pubKeyInterface)
	fmt.Println("RSA key pair generated successfully!")
	return pubKeyInterface
}

func handShake(id string) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		os.Exit(1)
	}

	// Encode the private key to the PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyFile, err := os.Create(id + "_private_key.pem")
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		os.Exit(1)
	}
	err = pem.Encode(privateKeyFile, privateKeyPEM)
	err = privateKeyFile.Close()

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Encode the public key to the PEM format
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	publicKeyFile, err := os.Create(id + "_public_key.pem")
	if err != nil {
		fmt.Println("Error creating public key file:", err)
		os.Exit(1)
	}
	err = pem.Encode(publicKeyFile, publicKeyPEM)
	err = publicKeyFile.Close()

	by, err := os.ReadFile(id + "_public_key.pem")
	if err != nil {
		fmt.Println(err)
	}

	block, _ := pem.Decode(by)

	sr := base64.StdEncoding.EncodeToString(block.Bytes)
	return sr
}

func rsa256Enc(pubKey *rsa.PublicKey, msg []byte) []byte {
	cData, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, msg)
	if err != nil {
		fmt.Printf("%v", err.Error())
	}
	return cData
}
