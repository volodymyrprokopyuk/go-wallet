package crypto_test

import (
	"testing"

	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func slcEqual(a, b []byte) bool {
  if len(a) != len(b) {
    return false
  }
  for i := range a {
    if a[i] != b[i] {
      return false
    }
  }
  return true
}

func TestShl(t *testing.T) {
  cases := []struct{ bytes []byte; n int; exp []byte }{
    {[]byte{0xd3, 0xc6, 0x19}, 8, []byte{0xc6, 0x19, 0x0}},
    {[]byte{0xd3, 0xc6, 0x19}, 16, []byte{0x19, 0x0, 0x0}},
    {[]byte{0xd3, 0xc6, 0x19}, 24, []byte{0x0, 0x0, 0x0}},
  }
  for _, c := range cases {
    got := crypto.Shl(c.bytes, c.n)
    if !slcEqual(got, c.exp) {
      t.Errorf("incorrect Shl: expected %v, got %v", c.exp, got)
    }
  }
}

func TestShr(t *testing.T) {
  cases := []struct{ bytes []byte; n int; exp []byte }{
    {[]byte{0xd3, 0xc6, 0x19}, 8, []byte{0x0, 0xd3, 0xc6}},
    {[]byte{0xd3, 0xc6, 0x19}, 16, []byte{0x0, 0x0, 0xd3}},
    {[]byte{0xd3, 0xc6, 0x19}, 24, []byte{0x0, 0x0, 0x0}},
  }
  for _, c := range cases {
    got := crypto.Shr(c.bytes, c.n)
    if !slcEqual(got, c.exp) {
      t.Errorf("incorrect Shr: expected %v, got %v", c.exp, got)
    }
  }
}
