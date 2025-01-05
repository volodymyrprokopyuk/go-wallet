package key

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func addressEncode(addr []byte) string {
  hexAddr := fmt.Sprintf("%x", addr)
  hash := crypto.Keccak256([]byte(hexAddr))
  hexHash := fmt.Sprintf("%x", hash)
  chAddr := strings.Split(hexAddr, "")
  chHash := strings.Split(hexHash, "")
  var encAddr strings.Builder
  for i := range chAddr {
    h, _ := strconv.ParseInt(chHash[i], 16, 8)
    a := chAddr[i]
    if h >= 8 {
      a = strings.ToUpper(a)
    }
    encAddr.WriteString(a)
  }
  return encAddr.String()
}

var reUpper = regexp.MustCompile(`[A-F0-9]`)
var reLower = regexp.MustCompile(`[a-f0-9]`)

func addressVerify(hexAddr string) error {
  hash := crypto.Keccak256([]byte(strings.ToLower(hexAddr)))
  hexHash := fmt.Sprintf("%x", hash)
  chAddr := strings.Split(hexAddr, "")
  chHash := strings.Split(hexHash, "")
  for i := range hexAddr {
    h, _ := strconv.ParseInt(chHash[i], 16, 8)
    a := chAddr[i]
    if h >= 8 && !reUpper.MatchString(a) || h < 8 && !reLower.MatchString(a) {
      return fmt.Errorf("address verify: invalid checksum")
    }
  }
  return nil
}
