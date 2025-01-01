package main

import (
	"fmt"
	"os"
)

func main() {
  cmd := walletCmd()
  err := cmd.Execute()
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }
}
