package key

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func AddressDerive(pub []byte) ([]byte, error) {
  switch {
  case len(pub) == 65 && pub[0] == 0x04:
  case len(pub) == 33 && (pub[0] == 0x02 || pub[0] == 0x03):
    pubx, puby := ecc.UnmarshalCompressed(ecc.P256k1(), pub)
    pub = NewPubKey(pubx, puby).Pub
  default:
    return nil, fmt.Errorf("address derive: invalid public key: %x", pub)
  }
  hash := crypto.Keccak256(pub[1:])
  addr := hash[12:]
  return addr, nil
}

func AddressEncode(addr []byte) string {
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

func AddressVerify(hexAddr string) error {
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
