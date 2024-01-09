package DualAuth

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// creates JWT with EDDSA is signing method, inputted key should be the private key, and public key used to verify
func createJWT(username string, issuer string, privKey []byte) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   username,
		Audience:  nil,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        "",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	// make sure that the private key is for EDDSA, ie a ed25519 private key
	signedToken, err := token.SignedString(privKey)

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func validateJWT(username string, issuer string, pubKey []byte) (bool, error) {

	return true, nil
}
