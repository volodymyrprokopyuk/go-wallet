package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
	"github.com/volodymyrprokopyuk/go-wallet/key"
)

func walletCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "wallet",
    Usage: "EC key pairs, a HD wallet, cryptographic functions",
    Version: "0.1.0",
    Commands: []*cli.Command{
      // EC key pairs, ECDSA sign and verify, Ethereum address
      key.KeyCmd(), key.AddressCmd(),
      // HD wallet, mnemonics, seeds
      key.MnemonicCmd(), key.SeedCmd(),
      // Cryptographic functions
      crypto.SHA256Cmd(), crypto.Keccak256Cmd(), crypto.HMACSHA512Cmd(),
      crypto.PBKDF2SHA512Cmd(), crypto.Base58CheckCmd(),
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
