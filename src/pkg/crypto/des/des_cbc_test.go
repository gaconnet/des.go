package des

import (
  "bytes"
  "crypto/cipher"
  "testing"
)

var cbcDES3Tests = []struct {
  key []byte
  iv  []byte
  in  []byte
  out []byte
}{
  {
    commonKey24,
    zeroIV8,
    []byte{1, 2, 3, 4, 5, 6, 7, 8},
    []byte{0x2e, 0xe4, 0xfc, 0x93, 0x96, 0x7, 0x7e, 0xd},
  },
}

func TestCBC_DES3(t *testing.T) {
  for _, tt := range cbcDES3Tests {
    c, err := NewDES3Cipher(tt.key)
    if err != nil {
      t.Errorf("NewDES3Cipher(%d bytes) = %s", len(tt.key), err)
      continue
    }

    encrypter := cipher.NewCBCEncrypter(c, tt.iv)
    d := make([]byte, len(tt.in))
    encrypter.CryptBlocks(d, tt.in)
    if !bytes.Equal(tt.out, d) {
      t.Errorf("CBCEncrypter\nhave %x\nwant %x", d, tt.out)
    }

    decrypter := cipher.NewCBCDecrypter(c, tt.iv)
    p := make([]byte, len(d))
    decrypter.CryptBlocks(p, d)
    if !bytes.Equal(tt.in, p) {
      t.Errorf("CBCDecrypter\nhave %x\nwant %x", p, tt.in)
    }
  }
}
