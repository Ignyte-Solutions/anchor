package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

func SignBytes(privateKey ed25519.PrivateKey, message []byte) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid private key length")
	}
	signature := ed25519.Sign(privateKey, message)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifySignature(publicKey ed25519.PublicKey, message []byte, signatureB64 string) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid public key length")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, err
	}
	if len(signature) != ed25519.SignatureSize {
		return false, errors.New("invalid signature length")
	}
	return ed25519.Verify(publicKey, message, signature), nil
}
