package crypto

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

func PBKDF2SHA512(pass, salt []byte, iter, keyLen int) []byte {
  return pbkdf2.Key(pass, salt, iter, keyLen, sha512.New)
}
