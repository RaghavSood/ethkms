package signer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// KmsSigner represents an AWS KMS based Ethereum signer
type KmsSigner struct {
	kmsClient *kms.Client
	keyID     string
	address   common.Address
	pubKey    *ecdsa.PublicKey
	chainID   *big.Int
}

// NewKmsSigner creates a new KMS signer instance
func NewKmsSigner(ctx context.Context, kmsClient *kms.Client, keyID string, chainID *big.Int) (*KmsSigner, error) {
	pubKey, err := GetPublicKey(ctx, kmsClient, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	address := crypto.PubkeyToAddress(*pubKey)

	return &KmsSigner{
		kmsClient: kmsClient,
		keyID:     keyID,
		address:   address,
		pubKey:    pubKey,
		chainID:   chainID,
	}, nil
}

// Address returns the Ethereum address associated with the KMS key
func (s *KmsSigner) Address() common.Address {
	return s.address
}

// SignHash signs an arbitrary hash using the KMS key
func (s *KmsSigner) SignHash(ctx context.Context, hash []byte) ([]byte, []byte, error) {
	r, sv, err := signHashWithKMS(ctx, s.kmsClient, s.keyID, hash)
	if err != nil {
		return nil, nil, err
	}

	signature, err := constructEthereumSignature(s.pubKey, hash, r, sv)
	if err != nil {
		return nil, nil, err
	}

	return hash, signature, nil
}

// PersonalSign implements eth_personalSign
func (s *KmsSigner) PersonalSign(ctx context.Context, message []byte) ([]byte, []byte, error) {
	prefixedHash := crypto.Keccak256(
		[]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)),
	)

	return s.SignHash(ctx, prefixedHash)
}

// CreateTransactOpts creates bind.TransactOpts for use with abigen generated contracts
func (s *KmsSigner) CreateTransactOpts(ctx context.Context) *bind.TransactOpts {
	return &bind.TransactOpts{
		From: s.address,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != s.address {
				return nil, bind.ErrNotAuthorized
			}

			signer := types.LatestSignerForChainID(s.chainID)
			hash := signer.Hash(tx)

			_, signature, err := s.SignHash(ctx, hash.Bytes())
			if err != nil {
				return nil, err
			}

			return tx.WithSignature(signer, signature)
		},
	}
}
