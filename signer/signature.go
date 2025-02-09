package signer

import (
	"crypto/ecdsa"
	"math/big"

	"bytes"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

func constructEthereumSignature(pubKey *ecdsa.PublicKey, hash, r, s []byte) ([]byte, error) {
	// Normalize S value according to Ethereum rules
	sBigInt := new(big.Int).SetBytes(s)
	if sBigInt.Cmp(secp256k1HalfN) > 0 {
		sBigInt.Sub(secp256k1N, sBigInt)
		s = sBigInt.Bytes()
	}

	// Construct base signature without recovery ID
	signature := make([]byte, 65)
	copy(signature[0:32], normalizeSignatureLength(r))
	copy(signature[32:64], normalizeSignatureLength(s))

	// Get the expected public key bytes for comparison
	expectedPubKeyBytes := secp256k1.S256().Marshal(pubKey.X, pubKey.Y)

	for i := 0; i < 2; i++ {
		signature[64] = byte(i)
		recoveredPub, err := crypto.Ecrecover(hash, signature)
		if err == nil && bytes.Equal(recoveredPub, expectedPubKeyBytes) {
			return signature, nil
		}
	}

	return nil, ErrSignatureRecoveryFailed
}

func normalizeSignatureLength(sigValue []byte) []byte {
	trimmedSigValue := bytes.TrimLeft(sigValue, "\x00")

	for len(trimmedSigValue) < 32 {
		zeroBuf := []byte{0}
		trimmedSigValue = append(zeroBuf, trimmedSigValue...)
	}

	return trimmedSigValue
}
