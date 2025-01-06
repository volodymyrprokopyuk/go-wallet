package crypto

import (
	"bytes"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const alpha58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var digit58 = func() map[uint8]int64 {
  m := make(map[uint8]int64)
  for i := range alpha58 {
    m[alpha58[i]] = int64(i)
  }
  return m
}()

func strReverse(str string) string {
  var rev strings.Builder
  for i := len(str) - 1; i >= 0; i-- {
    rev.WriteByte(str[i])
  }
  return rev.String()
}

var reLeadZero = regexp.MustCompile(`^0+`)

func Base58Enc(hex []byte) string {
  zero, base58 := big.NewInt(0), big.NewInt(58)
  quot, rem := new(big.Int).SetBytes(hex), big.NewInt(0)
  var rev strings.Builder
  for quot.Cmp(zero) != 0 {
    quot.DivMod(quot, base58, rem)
    rev.WriteByte(alpha58[rem.Int64()])
  }
  leadZero := reLeadZero.FindString(fmt.Sprintf("%x", hex))
  leadOne := strings.Repeat("1", len(leadZero) / 2)
  str := leadOne + strReverse(rev.String())
  return str
}

var reLeadOne = regexp.MustCompile(`^1+`)

func Base58Dec(str string) ([]byte, error) {
  num, base58 := big.NewInt(0), big.NewInt(58)
  for i := 0; i < len(str); i ++ {
    digit, exist := digit58[str[i]]
    if !exist {
      return nil, fmt.Errorf("base58 decode: invalid digit: %c", str[i])
    }
    num.Mul(num, base58)
    num.Add(num, big.NewInt(digit))
  }
  leadOne := reLeadOne.FindString(str)
  leadZero := bytes.Repeat([]byte{0x0}, len(leadOne))
  hex := append(leadZero, num.Bytes()...)
  return hex, nil
}

func Base58CheckEnc(hex []byte) string {
  csum := SHA256(SHA256(hex))
  data := append(hex, csum[:4]...)
  str := Base58Enc(data)
  return str
}

func Base58CheckDec(str string) ([]byte, error) {
  data, err := Base58Dec(str)
  if err != nil {
    return nil, err
  }
  l := len(data) - 4
  hex, csum := data[:l], data[l:]
  hash := SHA256(SHA256(hex))
  if !bytes.Equal(hash[:4], csum) {
    return nil, fmt.Errorf("base58check decode: invalid checksum")
  }
  return hex, nil
}
