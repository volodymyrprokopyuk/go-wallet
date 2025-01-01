package key

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func formatKey(key *ecdsa.PrivateKey) string {
  return fmt.Sprintf("{prv: %064x, pub: %064x%064x}", key.D, key.X, key.Y)
}

func KeyCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "key",
    Short: "Generate a secp256k1 key pair, sign a message, verify a signature",
  }
  cmd.AddCommand(
    keyGenerateCmd(), keyDeriveCmd(), keyAddressCmd(),
    // signCmd(), verifyCmd(),
  );
  return cmd
}

func keyGenerateCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "generate",
    Short: `Generate a secp256k1 key pair
  stdout: a key pair in hex in yaml {prv, pub}`,
    RunE: func(cmd *cobra.Command, args []string) error {
      key, err := keyGenerate()
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", formatKey(key))
      return nil
    },
  }
  return cmd
}

func keyDeriveCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "derive",
    Short: `Derive a secp256k1 public key from an external private key
  stdin: an external private key in hex
  stdout: a key pair in hex in yaml {prv, pub}`,
    RunE: func(cmd *cobra.Command, args []string) error {
      var prv []byte
      _, err := fmt.Scanf("%x", &prv)
      if err != nil {
        return err
      }
      key := keyDerive(prv)
      fmt.Printf("%s\n", formatKey(key))
      return nil
    },
  }
  return cmd
}

func keyAddressCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "address",
    Short: `Derive Ethereum address from a public key
  stdin: a public key in hex
  stdout: the Ethereum address in hex`,
    RunE: func(cmd *cobra.Command, args []string) error{
      var pub []byte
      _, err := fmt.Scanf("%x", &pub)
      if err != nil {
        return err
      }
      addr := keyAddress(pub)
      fmt.Printf("%x\n", addr)
      return nil
    },
  }
  return cmd
}

// func signCmd() *cobra.Command {
//   cmd := &cobra.Command{
//     Use: "sign",
//     Short: `Sign a message with a private key
//   stdin: a hash of the message
//   stdout: the signature of the message`,
//     RunE: func(cmd *cobra.Command, args []string) error {
//       key, _ := cmd.Flags().GetString("key")
//       var hash string
//       _, err := fmt.Fscanf(os.Stdin, "%s", &hash)
//       if err != nil {
//         return err
//       }
//       sig, err := sign(key, []byte(hash))
//       if err != nil {
//         return err
//       }
//       fmt.Println(base64.StdEncoding.EncodeToString(sig))
//       return nil
//     },
//   }
//   cmd.Flags().String("key", "", "private key")
//   _ = cmd.MarkFlagRequired("key")
//   return cmd
// }

// func verifyCmd() *cobra.Command {
//   cmd := &cobra.Command{
//     Use: "verify",
//     Short: `Verify a signature given a message and a public key
//   stdin: a hash of the message
//   stdout: true if the signature is valid, false otherwise`,
//     RunE: func(cmd *cobra.Command, args []string) error {
//       var hash string
//       _, err := fmt.Fscanf(os.Stdin, "%s", &hash)
//       if err != nil {
//         return err
//       }
//       ssig, _ := cmd.Flags().GetString("sig")
//       sig, err := base64.StdEncoding.DecodeString(ssig)
//       if err != nil {
//         return err
//       }
//       pub, _ := cmd.Flags().GetString("pub")
//       valid, err := verify([]byte(hash), sig, pub)
//       if err != nil {
//         return err
//       }
//       fmt.Println(valid)
//       return nil
//     },
//   }
//   cmd.Flags().String("sig", "", "message signature")
//   _ = cmd.MarkFlagRequired("pub")
//   cmd.Flags().String("pub", "", "public key")
//   _ = cmd.MarkFlagRequired("pub")
//   return cmd
// }

func AddressCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "address",
    Short: "Encode and verify an Ethereum address (ERC-55)",
  }
  cmd.AddCommand(addrEncodeCmd(), addrVerifyCmd())
  return cmd
}

func addrEncodeCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "encode",
    Short: `Encode an Ethereum address (ERC-55)
  stdin: an address in hex
  stdout: the encoded address in hex`,
    RunE: func(cmd *cobra.Command, args []string) error {
      var addr string
      _, err := fmt.Scanf("%s", &addr)
      if err != nil {
        return err
      }
      encAddr := addressEncode(addr)
      fmt.Printf("%s\n", encAddr)
      return nil
    },
  }
  return cmd
}

func addrVerifyCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "verify",
    Short: `Verify an encoded Ethereum address (ERC-55)
  stdin: an encoded address in hex
  stdout: true if the address is valid, false otherwise`,
    RunE: func(cmd *cobra.Command, args []string) error {
      var addr string
      _, err := fmt.Scanf("%s", &addr)
      if err != nil {
        return err
      }
      valid := true
      err = addressVerify(addr)
      if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        valid = false
      }
      fmt.Printf("%t\n", valid)
      return nil
    },
  }
  return cmd
}

func SeedCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "seed",
    Short: "Generate, recover, derive seed",
  }
  cmd.AddCommand(seedGenerateCmd(), seedVerifyCmd(), seedDeriveCmd())
  return cmd
}

func seedGenerateCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "generate",
    Short: `Generate a random seed and encode it into a mnemonic (BIP-39)
  stdin: a optional randomly generated seed in hex if --stdin
  stdout: a generated or received seed encoded into a mnemonic string`,
    RunE: func(cmd *cobra.Command, args []string) error {
      bits, _ := cmd.Flags().GetInt("bits")
      stdin, _ := cmd.Flags().GetBool("stdin")
      var seed []byte
      if stdin {
        _, err := fmt.Scanf("%x", &seed)
        if err != nil {
          return err
        }
      }
      mnemonic, err := seedGenerage(bits, seed)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnemonic)
      return nil
    },
  }
  cmd.Flags().Int("bits", 0, "a seed length in bits")
  _ = cmd.MarkFlagRequired("bits")
  cmd.Flags().Bool("stdin", false, "receive a random seed from the stdin")
  return cmd
}

func seedVerifyCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "verify",
    Short: `Verify a mnemonic string against the checksum
  stdin: a mnemonic string
  stdout: true if the mnemonic is valid, false otherwise`,
    RunE: func(cmd *cobra.Command, args []string) error {
      var mnemonic []byte
      mnemonic, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      valid := true
      err = seedVerify(string(mnemonic))
      if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        valid = false
      }
      fmt.Printf("%t\n", valid)
      return nil
    },
  }
  return cmd
}

func seedDeriveCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "derive",
    Short: `Derive a seed from a mnemonic string
  stdin: a mnemonic string
  stdout: a seed in hex`,
    RunE: func(cmd *cobra.Command, args []string) error {
      passphrase, _ := cmd.Flags().GetString("passphrase")
      var mnemonic []byte
      mnemonic, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      seed := seedDerive(string(mnemonic), passphrase)
      fmt.Printf("%x\n", seed)
      return nil
    },
  }
  cmd.Flags().String("passphrase", "", "a passphrase")
  return cmd
}
