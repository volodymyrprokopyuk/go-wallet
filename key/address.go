package key

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/volodymyrprokopyuk/solidity-dex/wallet/crypto"
)

func addressEncode(addr string) string {
  addr = strings.ToLower(addr)
  hash := crypto.Keccak256([]byte(addr))
  hexAddr := strings.Split(addr, "")
  hexHash := strings.Split(fmt.Sprintf("%x", hash), "")
  var encAddr strings.Builder
  for i := range addr {
    h, _ := strconv.ParseInt(hexHash[i], 16, 8)
    a := hexAddr[i]
    if h >= 8 {
      a = strings.ToUpper(a)
    }
    _, _ = encAddr.WriteString(a)
  }
  return encAddr.String()
}

func addressVerify(addr string) error {
  hash := crypto.Keccak256([]byte(strings.ToLower(addr)))
  hexAddr := strings.Split(addr, "")
  hexHash := strings.Split(fmt.Sprintf("%x", hash), "")
  reUpper := regexp.MustCompile(`[A-F0-9]`)
  reLower := regexp.MustCompile(`[a-f0-9]`)
  // valid := true
  for i := range addr {
    h, _ := strconv.ParseInt(hexHash[i], 16, 8)
    a := hexAddr[i]
    if h >= 8 && !reUpper.MatchString(a) || h < 8 && !reLower.MatchString(a) {
      return fmt.Errorf("address verify: checksum mismatch")
      // valid = false
      // break
    }
  }
  // return valid
  return nil
}
