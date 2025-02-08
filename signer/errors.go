package signer

import "errors"

var (
	ErrSignatureRecoveryFailed = errors.New("failed to recover public key from signature")
	ErrInvalidSignatureLength  = errors.New("invalid signature length")
)
