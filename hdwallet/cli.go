package hdwallet

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

func ECKeyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "eckey",
    Usage: "Generate a secp256k1 key pair. Derive a secp256k1 public key",
    Commands: []*cli.Command{
      ecKeyGenerateCmd(), ecKeyDeriveCmd(),
    },
  }
  return cmd
}

func ecKeyGenerateCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "generate",
    Usage: `Generate a secp256k1 key pair
  stdout: a secp256k1 key pair in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      key, err := ECKeyGenerate()
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", key.YAMLEncode())
      return nil
    },
  }
  return cmd
}

func ecKeyDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a secp256k1 public key from an external secp256k1 private key
  stdin: an external secp256k1 private key in hex
  stdout: a secp256k1 key pair in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var prv []byte
      _, err := fmt.Scanf("%x", &prv)
      if err != nil {
        return err
      }
      key := ECKeyDerive(prv)
      fmt.Printf("%s\n", key.YAMLEncode())
      return nil
    },
  }
  return cmd
}

func ECDSACmd() *cli.Command {
  cmd := &cli.Command{
    Name: "ecdsa",
    Usage: "Sign a hash using the ECDSA. Verify a signature. Recover a public key",
    Commands: []*cli.Command{
      ecdsaSignCmd(), ecdsaVerifyCmd(), ecdsaRecoverCmd(),
    },
  }
  return cmd
}

func ecdsaSignCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "sign",
    Usage: `Sign a hash using the ECDSA over the secp256k1 elliptic curve
  stdin: a hash in hex
  stdout: a signature of the hash in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var prv []byte
      _, err := fmt.Sscanf(cmd.String("prv"), "%x", &prv)
      if err != nil {
        return err
      }
      var hash []byte
      _, err = fmt.Scanf("%x", &hash)
      if err != nil {
        return err
      }
      sig, err := ECDSASign(hash, []byte(prv))
      if err != nil {
        return err
      }
      fmt.Printf("%x\n", sig)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "prv", Usage: "a private key in hex", Required: true,
    },
  }
  return cmd
}

func ecdsaVerifyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "verify",
    Usage: `Verify a signature using the ECDSA over the secp256k1 elliptic curve
  stdin: a hash in hex
  stdout: true if the signature is valid, false otherwise`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var sig []byte
      _, err := fmt.Sscanf(cmd.String("sig"), "%x", &sig)
      if err != nil {
        return err
      }
      var pub []byte
      _, err = fmt.Sscanf(cmd.String("pub"), "%x", &pub)
      if err != nil {
        return err
      }
      var hash []byte
      _, err = fmt.Scanf("%x", &hash)
      if err != nil {
        return err
      }
      valid := true
      err = ECDSAVerify(hash, sig, pub)
      if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        valid = false
      }
      fmt.Printf("%t\n", valid)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "sig", Usage: "a signature in hex", Required: true,
    },
    &cli.StringFlag{
      Name: "pub", Usage: "a public key in hex", Required: true,
    },
  }
  return cmd
}

func ecdsaRecoverCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "recover",
    Usage: `Recover a public key from a hash and its ECDSA signature
  stdin: a hash in hex
  stdout: a public key in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var sig []byte
      _, err := fmt.Sscanf(cmd.String("sig"), "%x", &sig)
      if err != nil {
        return err
      }
      var hash []byte
      _, err = fmt.Scanf("%x", &hash)
      if err != nil {
        return err
      }
      pub, err := ECDSARecover(hash, sig)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", pub.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "sig", Usage: "a signature in hex", Required: true,
    },
  }
  return cmd
}

func AddressCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "address",
    Usage: "Derive, encode and verify an Ethereum address (ERC-55)",
    Commands: []*cli.Command{
      addressDeriveCmd(), addressEncodeCmd(), addressVerifyCmd(),
    },
  }
  return cmd
}

func addressDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive an Ethereum address from a secp256k1 public key
  stdin: a compressed or uncompressed secp256k1 public key in hex
  stdout: an Ethereum address in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var pub []byte
      _, err := fmt.Scanf("%x", &pub)
      if err != nil {
        return err
      }
      addr, err := AddressDerive(pub)
      if err != nil {
        return err
      }
      fmt.Printf("%x\n", addr)
      return nil
    },
  }
  return cmd
}

func addressEncodeCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "encode",
    Usage: `Encode an Ethereum address (ERC-55)
  stdin: an Ethereum address in hex
  stdout: an encoded case-sensitive Ethereum address string`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var addr []byte
      _, err := fmt.Scanf("%x", &addr)
      if err != nil {
        return err
      }
      encAddr := AddressEncode(addr)
      fmt.Printf("%s\n", encAddr)
      return nil
    },
  }
  return cmd
}

func addressVerifyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "verify",
    Usage: `Verify an encoded case-sensitive Ethereum address (ERC-55)
  stdin: an encoded case-sensitive Ethereum address string
  stdout: true if the address is valid, false otherwise`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var addr string
      _, err := fmt.Scanf("%s", &addr)
      if err != nil {
        return err
      }
      valid := true
      err = AddressVerify(addr)
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

func MnemonicCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "mnemonic",
    Usage: "Generate, derive, and verify a mnemonic (BIP-39)",
    Commands: []*cli.Command{
      mnemonicGenerateCmd(), mnemonicDeriveCmd(), mnemonicVerifyCmd(),
    },
  }
  return cmd
}

func mnemonicGenerateCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "generate",
    Usage: `Generate a mnemonic that encodes a random sequence of bytes (BIP-39)
  stdout: a mnemonic string that encodes a random sequence of bytes`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      bits := cmd.Int("bits")
      mnem, err := MnemonicGenerate(int(bits))
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnem)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "bits", Usage: "a length in bits of a random sequence of bytes",
      Required: true,
    },
  }
  return cmd
}

func mnemonicDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a mnemonic that encodes an external random sequence of bytes (BIP-39)
  stdin: a random sequence of bytes in hex
  stdout: a mnemonic string that encodes the external random sequence of bytes`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      bits := cmd.Int("bits")
      var rseq []byte
      _, err := fmt.Scanf("%x", &rseq)
      if err != nil {
        return err
      }
      mnem, err := MnemonicDerive(int(bits), rseq)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnem)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "bits", Usage: "a length in bits of a random sequence of bytes",
      Required: true,
    },
  }
  return cmd
}

func mnemonicVerifyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "verify",
    Usage: `Verify a mnemonic string against the embedded checksum (BIP-39)
  stdin: a mnemonic string
  stdout: true if the mnemonic is valid, false otherwise`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      valid := true
      err = MnemonicVerify(string(mnem))
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

func HDCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "hd",
    Usage: "Derive extended master and child private and public keys",
    Commands: []*cli.Command{
      seedDeriveCmd(), masterDeriveCmd(), privateDeriveCmd(),
      hardenedDeriveCmd(), publicDeriveCmd(), pathDeriveCmd(), ekeyDecodeCmd(),
    },
  }
  return cmd
}

func seedDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "seed",
    Usage: `Derive a seed from a mnemonic and an optional passphrase
  stdin: a mnemonic string
  stdout: a seed in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      pass := cmd.String("passphrase")
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      seed := SeedDerive(string(mnem), pass)
      fmt.Printf("%x\n", seed)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "passphrase", Usage: "a passphrase string",
    },
  }
  return cmd
}

func masterDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "master",
    Usage: `Derive extended master private and public keys from a seed
  stdin: a seed in hex
  stdout: extended master private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var seed []byte
      _, err := fmt.Scanf("%x", &seed)
      if err != nil {
        return err
      }
      ekey := MasterDerive(seed)
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  return cmd
}

func privateDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "private",
    Usage: `Derive extended private and public keys from an extended parent private key
  stdin: an extended parent private key in hex
  stdout: extended child private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      depth, index := cmd.Int("depth"), cmd.Int("index")
      var prve []byte
      _, err := fmt.Scanf("%x", &prve)
      if err != nil {
        return err
      }
      ekey := PrivateDerive(prve, uint8(depth), uint32(index))
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "depth", Usage: "a depth of the child key from the master key",
      Required: true,
    },
    &cli.IntFlag{
      Name: "index", Usage: "an index of the child key from the parent key",
      Required: true,
    },
  }
  return cmd
}

func hardenedDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "hardened",
    Usage: `Derive hardened extended private and public keys from an extended parent private key
  stdin: an extended parent private key in hex
  stdout: hardened extended child private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      depth, index := cmd.Int("depth"), cmd.Int("index")
      var prve []byte
      _, err := fmt.Scanf("%x", &prve)
      if err != nil {
        return err
      }
      ekey := HardenedDerive(prve, uint8(depth), uint32(index))
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "depth", Usage: "a depth of the child key from the master key",
      Required: true,
    },
    &cli.IntFlag{
      Name: "index", Usage: "an index of the child key from the parent key",
      Required: true,
    },
  }
  return cmd
}

func publicDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "public",
    Usage: `Derive an extended public key from an extended parent public key
  stdin: an extended parent public key in hex
  stdout: an extended child public key in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      depth, index := cmd.Int("depth"), cmd.Int("index")
      var pube []byte
      _, err := fmt.Scanf("%x", &pube)
      if err != nil {
        return err
      }
      ekey := PublicDerive(pube, uint8(depth), uint32(index))
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "depth", Usage: "a depth of the child key from the master key",
      Required: true,
    },
    &cli.IntFlag{
      Name: "index", Usage: "an index of the child key from the parent key",
      Required: true,
    },
  }
  return cmd
}

func pathDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "path",
    Usage: `Derive extended private and public keys defined by a HD path
  stdin: a mnemonic string
  stdout: extended private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      pass := cmd.String("passphrase")
      path := cmd.String("path")
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      ekey, err := PathDerive(string(mnem), pass, path)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "passphrase", Usage: "a passphrase string",
    },
    &cli.StringFlag{
      Name: "path", Usage: "a HD path e.g. m/0'/1", Required: true,
    },
  }
  return cmd
}

func ekeyDecodeCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "decode",
    Usage: `Decode a base58 encoded extended private or public key
  stdin: a base58 encoded extended private or public key
  stdout: an extended private or public key in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var str string
      _, err := fmt.Scanf("%s", &str)
      if err != nil {
        return err
      }
      ekey, err := EkeyDecode(str)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  return cmd
}
