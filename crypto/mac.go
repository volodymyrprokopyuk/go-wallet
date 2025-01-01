package crypto

import (
	"crypto/hmac"
	"crypto/sha512"
)

func HMACSHA512(data, key []byte) []byte {
  state := hmac.New(sha512.New, key)
  _, _ = state.Write(data)
  mac := state.Sum(nil)
  return mac
}
