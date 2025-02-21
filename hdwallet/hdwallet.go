package hdwallet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

var (
  xprvVer = []byte{0x04, 0x88, 0xad, 0xe4}
  xpubVer = []byte{0x04, 0x88, 0xb2, 0x1e}
)

func EkeyEncode(
  version []byte, depth uint8, parent []byte, index uint32, code, key []byte,
) string {
  var data bytes.Buffer
  data.Write(version)
  data.Write([]byte{depth})
  switch {
  case parent == nil: // Master key
    data.Write([]byte{0x00, 0x00, 0x00, 0x00})
  case len(parent) == 4: // Parent hash
    data.Write(parent)
  default: // Parent pubc
    hash := crypto.RIPEMD160(crypto.SHA256(parent))
    data.Write(hash[:4])
  }
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data.Write(idx)
  data.Write(code)
  if len(key) == 32 { // Private key
    data.Write([]byte{0x00})
  }
  data.Write(key)
  csum := crypto.SHA256(crypto.SHA256(data.Bytes()))
  data.Write(csum[:4])
  str := crypto.Base58Enc(data.Bytes())
  return str
}

func EkeyDecode(str string) (*ExtKey, error) {
  data, err := crypto.Base58Dec(str)
  if err != nil {
    return nil, err
  }
  csum := data[78:]
  hash := crypto.SHA256(crypto.SHA256(data[:78]))
  if !slices.Equal(hash[:4], csum) {
    return nil, fmt.Errorf("extended key decode: invalid checksum")
  }
  version := data[:4]
  depth := uint8(data[4])
  parent := data[5:9]
  index := binary.BigEndian.Uint32(data[9:13])
  code := data[13:45]
  if slices.Equal(version, xprvVer) { // Decode a private key
    prv := data[46:78]
    key := ECKeyDerive(prv)
    ekey := &ExtKey{PrvKey: *key, Code: code, Depth: depth, Index: index}
    ekey.Xprv = EkeyEncode(xprvVer, depth, parent, index, code, ekey.Prv)
    ekey.Xpub = EkeyEncode(xpubVer, depth, parent, index, code, ekey.Pubc)
    return ekey, nil
  } else { // Decode a public key
    pubc := data[45:78]
    pubx, puby := ecc.UnmarshalCompressed(ecc.P256k1(), pubc)
    ekey := NewExtPubKey(pubx, puby, code, depth, index)
    ekey.Xpub = EkeyEncode(xpubVer, depth, parent, index, code, ekey.Pubc)
    return ekey, nil
  }
}

func SeedDerive(mnemonic, passphrase string) []byte {
  salt := []byte("mnemonic" + passphrase)
  seed := crypto.PBKDF2SHA512([]byte(mnemonic), salt, 2048, 64)
  return seed
}

func MasterDerive(seed []byte) *ExtKey {
  depth, index := uint8(0), uint32(0)
  hmac := crypto.HMACSHA512(seed, []byte("Bitcoin seed"))
  prv, code := hmac[:32], hmac[32:]
  key := ECKeyDerive(prv)
  ekey := &ExtKey{PrvKey: *key, Code: code, Depth: depth, Index: index}
  ekey.Xprv = EkeyEncode(xprvVer, depth, nil, index, code, prv)
  ekey.Xpub = EkeyEncode(xpubVer, depth, nil, index, code, ekey.Pubc)
  return ekey
}

func PrivateDerive(prve []byte, depth uint8, index uint32) *ExtKey {
  parPrv, parCode := prve[:32], prve[32:]
  parKey := ECKeyDerive(parPrv)
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  var data bytes.Buffer
  data.Write(parKey.Pubc) // Parent public compressed
  data.Write(idx)
  hmac := crypto.HMACSHA512(data.Bytes(), parCode)
  prv, code := hmac[:32], hmac[32:]
  prvi := new(big.Int).SetBytes(prv)
  prvi.Add(prvi, new(big.Int).SetBytes(parPrv))
  prvi.Mod(prvi, ecc.P256k1().Params().N)
  key := ECKeyDerive(prvi.Bytes())
  ekey := &ExtKey{PrvKey: *key, Code: code, Depth: depth, Index: index}
  ekey.Xprv = EkeyEncode(xprvVer, depth, parKey.Pubc, index, code, ekey.Prv)
  ekey.Xpub = EkeyEncode(xpubVer, depth, parKey.Pubc, index, code, ekey.Pubc)
  return ekey
}

func HardenedDerive(prve []byte, depth uint8, index uint32) *ExtKey {
  parPrv, parCode := prve[:32], prve[32:]
  parKey := ECKeyDerive(parPrv) // Only for xprv and xpub
  index += uint32(1 << 31) // Hardened key index
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  var data bytes.Buffer
  data.WriteByte(0x00)
  data.Write(parPrv) // Parent private prefixed
  data.Write(idx)
  hmac := crypto.HMACSHA512(data.Bytes(), parCode)
  prv, code := hmac[:32], hmac[32:]
  prvi := new(big.Int).SetBytes(prv)
  prvi.Add(prvi, new(big.Int).SetBytes(parPrv))
  prvi.Mod(prvi, ecc.P256k1().Params().N)
  key := ECKeyDerive(prvi.Bytes())
  ekey := &ExtKey{PrvKey: *key, Code: code, Depth: depth, Index: index}
  ekey.Xprv = EkeyEncode(xprvVer, depth, parKey.Pubc, index, code, ekey.Prv)
  ekey.Xpub = EkeyEncode(xpubVer, depth, parKey.Pubc, index, code, ekey.Pubc)
  return ekey
}

func PublicDerive(pube []byte, depth uint8, index uint32) *ExtKey {
  parPubc, parCode := pube[:33], pube[33:]
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  var data bytes.Buffer
  data.Write(parPubc) // Parent public compressed
  data.Write(idx)
  hmac := crypto.HMACSHA512(data.Bytes(), parCode)
  pb, code := hmac[:32], hmac[32:]
  pub := new(ecdsa.PublicKey)
  pub.Curve = ecc.P256k1()
  pub.X, pub.Y = pub.ScalarBaseMult(pb)
  parX, parY := ecc.UnmarshalCompressed(ecc.P256k1(), parPubc)
  pubx, puby := pub.Add(pub.X, pub.Y, parX, parY)
  ekey := NewExtPubKey(pubx, puby, code, depth, index)
  ekey.Xpub = EkeyEncode(xpubVer, depth, parPubc, index, code, ekey.Pubc)
  return ekey
}

var rePrvPath = regexp.MustCompile(`^m(?:/\d+'?)*$`)
var rePrvSeg = regexp.MustCompile(`/(\d+)('?)`)
var rePubPath = regexp.MustCompile(`^M(?:/\d+)*$`)
var rePubSeg = regexp.MustCompile(`/(\d+)`)

func PathDerive(mnemonic, passphrase, path string) (*ExtKey, error) {
  if !rePrvPath.MatchString(path) && !rePubPath.MatchString(path) {
    return nil, fmt.Errorf("path derive: invalid path: %s", path)
  }
  seed := SeedDerive(mnemonic, passphrase)
  ekey := MasterDerive(seed)
  depth := uint8(0)
  if strings.HasPrefix(path, "m") { // Private key derivation
    for _, seg := range rePrvSeg.FindAllStringSubmatch(path, -1) {
      depth++
      index, _ := strconv.ParseInt(seg[1], 10, 32)
      hardened := len(seg[2]) != 0
      prve := append(ekey.Prv, ekey.Code...)
      if hardened {
        ekey = HardenedDerive(prve, depth, uint32(index))
      } else {
        ekey = PrivateDerive(prve, depth, uint32(index))
      }
    }
  } else { // Public key derivation
    for _, seg := range rePubSeg.FindAllStringSubmatch(path, -1) {
      depth++
      index, _ := strconv.ParseInt(seg[1], 10, 32)
      pube := append(ekey.Pubc, ekey.Code...)
      ekey = PublicDerive(pube, depth, uint32(index))
    }
  }
  return ekey, nil
}
