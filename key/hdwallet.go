package key

import "github.com/volodymyrprokopyuk/go-wallet/crypto"

func masterDerive(seed []byte) *ecKey {
  hmac := crypto.HMACSHA512(seed, []byte("Bitcoin seed"))
  prv := hmac[:32]
  eckey := keyDerive(prv)
  eckey.code = hmac[32:]
  return eckey
}
