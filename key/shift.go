package key

func shl8(bs []byte, n int) []byte {
  sh := make([]byte, len(bs))
  i := 0
  for ; i < len(bs) - 1; i++ {
    sh[i] = bs[i] << n | bs[i + 1] >> (8 - n)
  }
  sh[i] = bs[i] << n
  return sh
}

func shr8(bs []byte, n int) []byte {
  sh := make([]byte, len(bs))
  i := len(bs) - 1
  for ; i > 0; i-- {
    sh[i] = bs[i] >> n | bs[i - 1] << (8 - n)
  }
  sh[i] = bs[i] >> n
  return sh
}

type shift func(bs []byte, n int) []byte

func makeShift(shift8 shift) shift {
  return func(bs []byte, n int) []byte {
    sh := bs
    for n > 8 {
      sh = shift8(sh, 8)
      n -= 8
    }
    if n > 0 {
      sh = shift8(sh, n)
    }
    return sh
  }
}

var Shl = makeShift(shl8)
var Shr = makeShift(shr8)
