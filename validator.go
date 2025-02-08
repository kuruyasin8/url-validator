package validator

import (
	"crypto"
	"crypto/sha256"
	"crypto/rsa"
	"encoding/base64"
)

type Policy struct {
	Expiration  int64  `json:"expiration"`
	ResourceURL string `json:"resource_url"`
}

type Validator struct {
	PublicKey *rsa.PublicKey
}

func NewValidator(publicKey *rsa.PublicKey) *Validator {
	return &Validator{
		PublicKey: publicKey,
	}
}

func (v *Validator) Validate(signature, policy string) (*Policy, error) {
	verifiedPolicy, err := new(Policy).Bind(policy)
	if err != nil {
		return nil, err
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256([]byte(policy))

	err = rsa.VerifyPKCS1v15(v.PublicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return nil, err
	}

	return verifiedPolicy, nil
}