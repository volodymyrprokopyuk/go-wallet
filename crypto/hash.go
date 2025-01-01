package crypto

import (
	"crypto/sha256"

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
