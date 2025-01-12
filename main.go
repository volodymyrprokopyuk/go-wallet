package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
	"github.com/volodymyrprokopyuk/go-wallet/hdwallet"
)

func walletCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "wallet",
    Usage: "EC keys and signatures, a HD wallet, cryptographic functions",
    Version: "0.1.0",
    Commands: []*cli.Command{
      hdwallet.ECKeyCmd(), hdwallet.AddressCmd(),
      hdwallet.MnemonicCmd(), hdwallet.HDCmd(),
      crypto.SHA256Cmd(), crypto.Keccak256Cmd(), crypto.HMACSHA512Cmd(),
      crypto.PBKDF2SHA512Cmd(), crypto.Base58Cmd(), crypto.Base58CheckCmd(),
    },
  }
  return cmd
}

func main() {
  err := walletCmd().Run(context.Background(), os.Args)
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }
}
