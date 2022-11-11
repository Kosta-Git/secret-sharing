package cryptography

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const separator = ";"

func PackRsaAndKeyShare(rsa *rsa.PrivateKey, keyShare []byte) (string, error) {
	rsaFormatted, err := x509.MarshalPKCS8PrivateKey(rsa)
	if err != nil {
		return "", err
	}

	format := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("%v%v%v", format(rsaFormatted), separator, format(keyShare)), nil
}

func UnpackRsaAndKeyShare(packed string) (*rsa.PrivateKey, []byte, error) {
	splits := strings.Split(packed, separator)
	if len(splits) != 2 {
		return nil, nil, errors.New("invalid packed secret format")
	}

	format := base64.RawStdEncoding.DecodeString

	// Retrieve RSA Private Key
	decodedDerString, err := format(splits[0])
	if err != nil {
		return nil, nil, errors.New("invalid der str")
	}
	rsaKeyInterface, err := x509.ParsePKCS8PrivateKey(decodedDerString)
	if err != nil {
		return nil, nil, errors.New("invalid der")
	}
	rsaKey, isRSAPrivateKey := rsaKeyInterface.(*rsa.PrivateKey)
	if isRSAPrivateKey != true {
		return nil, nil, errors.New("invalid key type")
	}

	// Retrieve Key Share
	decodedShare, err := format(splits[1])
	if err != nil {
		return nil, nil, errors.New("invalid share str")
	}

	return rsaKey, decodedShare, nil
}
