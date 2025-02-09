package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/RaghavSood/ethkms/signer"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func main() {
	ctx := context.Background()

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Create KMS client
	kmsSvc := kms.NewFromConfig(awsCfg)

	keyID := os.Getenv("KEY_ID")
	if keyID == "" {
		log.Fatal("KEY_ID environment variable is not set")
	}

	// Create signer
	ethSigner, err := signer.NewKmsSigner(ctx, kmsSvc, keyID, big.NewInt(1)) // chainID 1 for mainnet
	if err != nil {
		log.Fatalf("Failed to create KMS signer: %v", err)
	}

	address := ethSigner.Address()
	fmt.Printf("Ethereum Address: %s\n", address)

	// Sign a personal message
	message := []byte("Hello, Ethereum!")
	hash, signature, err := ethSigner.PersonalSign(ctx, message)
	if err != nil {
		log.Fatalf("Failed to sign personal message: %v", err)
	}

	fmt.Printf("Personal Message Signature: %s\n", hex.EncodeToString(signature))
	fmt.Printf("Personal Message Hash: %s\n", hex.EncodeToString(hash))

	// Sign a specific hash
	testHash, err := hex.DecodeString("5b001f2ad81fe86899545b51f8ecd1ca08674437d5c4748e1b70ba5dcf85ed86")
	if err != nil {
		log.Fatalf("Failed to decode test hash: %v", err)
	}

	fmt.Println("\n\n\n\n")
	signedHash, signature, err := ethSigner.SignHash(ctx, testHash)
	if err != nil {
		log.Fatalf("Failed to sign hash: %v", err)
	}

	fmt.Printf("\nRaw Hash Signature: %s\n", hex.EncodeToString(signature))
	fmt.Printf("Input Hash: %s\n", hex.EncodeToString(testHash))
	fmt.Printf("Signed Hash: %s\n", hex.EncodeToString(signedHash))

	// Use with contract (assuming you have a contract instance)
	// opts := ethSigner.CreateTransactOpts(ctx)
	// contract.SomeMethod(opts, arg1, arg2...)
}
