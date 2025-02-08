package signer

import (
	"crypto/ecdsa"
	"math/big"

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

	// Construct signature with recovery ID
	pubKeyBytes := secp256k1.S256().Marshal(pubKey.X, pubKey.Y)
	signature := make([]byte, 65)
	copy(signature[0:32], padTo32(r))
	copy(signature[32:64], padTo32(s))

	// Try recovery IDs 0 and 1
	for v := 0; v < 2; v++ {
		signature[64] = byte(v)
		recoveredPub, err := crypto.Ecrecover(hash, signature)
		if err != nil {
			continue
		}
		if string(recoveredPub) == string(pubKeyBytes) {
			return signature, nil
		}
	}

	return nil, ErrSignatureRecoveryFailed
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}
