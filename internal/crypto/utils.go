package crypto

import "crypto/rand"

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GeneratePadding() string {
	bytes, err := RandomBytes(16)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
