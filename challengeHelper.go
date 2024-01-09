package DualAuth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"time"
)

type auth interface {
	createChallenge(username string) (string, error)
	validateChallenge(N *big.Int, E int, challenge string, signed string) bool
}

// Creates challenge with some kind of timestamp/local information and nonce
// to eliminate the possibility of a repeat attack
func createChallenge(username string) (string, error) {

	nonce := make([]byte, 16) //uses 16 byte length nonce

	// error checking for the randomizatoin function
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// concatenating final string output
	result := username + time.Now().String() + hex.EncodeToString(nonce)

	return result, nil
}

// takes initial challenge string and the signed string and validates that the user signed it
// with their private key, uses the SHA256 hash function and RSAPSS signature scheme
func validateChallenge(N *big.Int, E int, challenge string, signed string) bool {

	pKey := rsa.PublicKey{N, E}

	hashFunc := crypto.SHA256.New()

	hashFunc.Write([]byte(challenge))

	err := rsa.VerifyPSS(&pKey, crypto.SHA256, hashFunc.Sum(nil), []byte(signed), nil)
	if err != nil {
		return false
	}
	return true
}
