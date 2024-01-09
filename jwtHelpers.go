package DualAuth

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func createJWT(username string, issuer string, signingKey []byte) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   username,
		Audience:  nil,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        "",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(signingKey)

	if err != nil {
		return "", err
	}

	return signedToken, nil
}
