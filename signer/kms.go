package signer

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

const (
	awsKmsSignMessageType      = "DIGEST"
	awsKmsSignSigningAlgorithm = "ECDSA_SHA_256"
)

type asn1EcSig struct {
	R, S asn1.RawValue
}

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

func GetPublicKey(ctx context.Context, svc *kms.Client, keyID string) (*ecdsa.PublicKey, error) {
	pubKey := keyCache.Get(keyID)
	if pubKey != nil {
		return pubKey, nil
	}

	derBytes, err := getPublicKeyDERBytes(ctx, svc, keyID)
	if err != nil {
		return nil, err
	}

	pubKey, err = crypto.UnmarshalPubkey(derBytes)
	if err != nil {
		return nil, err
	}

	keyCache.Add(keyID, pubKey)
	return pubKey, nil
}

func signHashWithKMS(ctx context.Context, svc *kms.Client, keyID string, hash []byte) ([]byte, []byte, error) {
	signOutput, err := svc.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		SigningAlgorithm: awsKmsSignSigningAlgorithm,
		MessageType:      awsKmsSignMessageType,
		Message:          hash,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign hash with KMS")
	}

	var sig asn1EcSig
	if _, err := asn1.Unmarshal(signOutput.Signature, &sig); err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal signature")
	}

	return sig.R.Bytes, sig.S.Bytes, nil
}

func getPublicKeyDERBytes(ctx context.Context, svc *kms.Client, keyID string) ([]byte, error) {
	getPubKeyOutput, err := svc.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS for KeyId=%s: %w", keyID, err)
	}

	var asn1pubk asn1EcPublicKey
	if _, err := asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk); err != nil {
		return nil, fmt.Errorf("failed to parse ASN1 public key for KeyId=%s: %w", keyID, err)
	}

	return asn1pubk.PublicKey.Bytes, nil
}
