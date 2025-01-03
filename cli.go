package main

import (
	"github.com/spf13/cobra"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
	"github.com/volodymyrprokopyuk/go-wallet/key"
)

func walletCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "wallet",
    Short: "EC key pairs, HD wallet, cryptographic functions",
    Version: "0.1.0",
    SilenceUsage: true,
    SilenceErrors: true,
  }
  cmd.AddCommand(
    crypto.HashCmd(), crypto.MACCmd(), crypto.KDFCmd(), crypto.Base58CheckCmd(),
    key.KeyCmd(), key.AddressCmd(), key.MnemonicCmd(), key.SeedCmd(),
  )
  return cmd
}
