package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

func SHA256(data []byte) []byte {
  state := sha256.New()
  _, _ = state.Write(data)
  hash := state.Sum(nil)
  return hash
}

func Keccak256(data []byte) []byte {
  state := sha3.NewLegacyKeccak256()
  _, _ = state.Write(data)
  hash := state.Sum(nil)
  return hash
}

func HMACSHA512(data, key []byte) []byte {
  state := hmac.New(sha512.New, key)
  _, _ = state.Write(data)
  mac := state.Sum(nil)
  return mac
}

func PBKDF2SHA512(pass, salt []byte, iter, keyLen int) []byte {
  return pbkdf2.Key(pass, salt, iter, keyLen, sha512.New)
}
