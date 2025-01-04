package key

import (
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func seedDerive(mnemonic, passphrase string) []byte {
  salt := []byte("mnemonic" + passphrase)
  seed := crypto.PBKDF2SHA512([]byte(mnemonic), salt, 2048, 64)
  return seed
}

func masterDerive(seed []byte) *ecKey {
  hmac := crypto.HMACSHA512(seed, []byte("Bitcoin seed"))
  prv := hmac[:32]
  key := keyDerive(prv)
  key.code = hmac[32:]
  return key
}

func privateDerive(prve []byte, index uint32) *ecKey {
  parPrv, parCode := prve[:32], prve[32:]
  parKey := keyDerive(parPrv)
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data := append(parKey.pubc, idx...) // parent public compressed
  hmac := crypto.HMACSHA512(data, parCode)
  prvi := new(big.Int).SetBytes(hmac[:32])
  prvi.Add(prvi, new(big.Int).SetBytes(parPrv))
  prvi.Mod(prvi, ecc.P256k1().Params().N)
  prv := prvi.Bytes()
  key := keyDerive(prv)
  key.code = hmac[32:]
  return key
}

func hardenedDerive(prve []byte, index uint32) *ecKey {
  parPrv, parCode := prve[:32], prve[32:]
  index += uint32(1 << 31)
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data := append([]byte{0x00}, parPrv...) // parent private prefixed
  data = append(data, idx...)
  hmac := crypto.HMACSHA512(data, parCode)
  prvi := new(big.Int).SetBytes(hmac[:32])
  prvi.Add(prvi, new(big.Int).SetBytes(parPrv))
  prvi.Mod(prvi, ecc.P256k1().Params().N)
  prv := prvi.Bytes()
  key := keyDerive(prv)
  key.code = hmac[32:]
  return key
}

func publicDerive(pube []byte, index uint32) *ecKey {
  parPubc, parCode := pube[:33], pube[33:]
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data := append([]byte{}, parPubc...) // parent public compressed
  data = append(data, idx...)
  hmac := crypto.HMACSHA512(data, parCode)
  pub := new(ecdsa.PublicKey)
  pub.Curve = ecc.P256k1()
  pub.X, pub.Y = pub.ScalarBaseMult(hmac[:32])
  parX, parY := ecc.UnmarshalCompressed(ecc.P256k1(), parPubc)
  pubx, puby := pub.Add(pub.X, pub.Y, parX, parY)
  code := hmac[32:]
  key := newECKey(nil, pubx, puby, code)
  return key
}
