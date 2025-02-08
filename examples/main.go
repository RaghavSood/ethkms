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
		log.Fatal(err)
	}

	// Create KMS client
	kmsSvc := kms.NewFromConfig(awsCfg)

	// Create signer
	ethSigner, err := signer.NewKmsSigner(ctx, kmsSvc, os.Getenv("KEY_ID"), big.NewInt(1)) // chainID 1 for mainnet
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ethSigner.Address())

	// Sign a personal message
	message := []byte("Hello, Ethereum!")
	hash, signature, err := ethSigner.PersonalSign(ctx, message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Signature:", hex.EncodeToString(signature))
	fmt.Println("Hash:", hex.EncodeToString(hash))

	hash, _ = hex.DecodeString("5b001f2ad81fe86899545b51f8ecd1ca08674437d5c4748e1b70ba5dcf85ed86")
	hash2, signature, err := ethSigner.SignHash(ctx, hash)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Signature:", hex.EncodeToString(signature))
	fmt.Println("Hash:", hex.EncodeToString(hash))
	fmt.Println("Hash2:", hex.EncodeToString(hash2))

	// Use with contract (assuming you have a contract instance)
	// opts := ethSigner.CreateTransactOpts(ctx)
	// contract.SomeMethod(opts, arg1, arg2...)
}
