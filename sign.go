package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func Generate64BitNonce() ([]byte, error) {

	result := make([]byte, 8)
	_, err := rand.Read(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func AppendBytes(a, b []byte) []byte {
	result := make([]byte, len(a)+len(b))

	for i := 0; i < len(a)+len(b); i++ {
		if i < len(a) {
			result[i] = a[i]
		} else {
			result[i] = b[i-len(a)]
		}
	}

	return result
}

func XorBytes(a, b []byte) ([]byte, error) {

	if len(a) != len(b) {
		return nil, fmt.Errorf("irregular length vectors for XOR (%d, %d)", len(a), len(b))
	}

	for i := 0; i < len(a); i++ {
		a[i] = a[i] ^ b[i]
	}

	return a, nil
}

func Uint64ToLittleEndian(u uint64) []byte {

	result := make([]byte, 8)

	for i := 0; i < 8; i++ {
		result[i] = byte(u >> (i * 8) & 0xFF)
	}

	return result
}

func EncryptAesCtr(data, key, nonce []byte) ([]byte, error) {

	blocksize := aes.BlockSize
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nblocks := len(data) / blocksize

	for nblocks*blocksize < len(data) {
		nblocks = nblocks + 1
	}

	keystream := make([]byte, len(data))
	for i := 0; i < nblocks; i++ {

		start, end := i*blocksize, (i+1)*blocksize
		plainblock := AppendBytes(nonce, Uint64ToLittleEndian(uint64(i)))
		cipherblock := make([]byte, blocksize)

		cipher.Encrypt(cipherblock, plainblock)

		for j := start; j < end && j < len(keystream); j++ {
			keystream[j] = cipherblock[j-start]
		}
	}

	xord, err := XorBytes(data, keystream)
	if err != nil {
		return nil, err
	}

	return xord, nil
}

func EncryptThenMAC(data, key, nonce []byte) ([]byte, error) {

	h := hmac.New(sha256.New, key)

	ciphertext, err := EncryptAesCtr(data, key, nonce)
	if err != nil {
		return nil, err
	}

	x := AppendBytes(nonce, ciphertext)
	h.Write(x)
	mac := h.Sum(nil)

	return AppendBytes(mac, x), nil

}

func DecryptWithMAC(data, key []byte) ([]byte, error) {

	if len(data) < 40 {
		return nil, fmt.Errorf("payload too short to contain MAC and nonce (%d)", len(data))
	}

	mac := data[:32]
	nonce := data[32:40]
	ciphertext := data[40:]

	// Check MAC
	h := hmac.New(sha256.New, key)
	h.Write(data[32:])
	test := h.Sum(nil)

	if !hmac.Equal(mac, test) {
		return nil, fmt.Errorf("MAC validation failed")
	}

	// Finally, decrypt
	plaintext, err := EncryptAesCtr(ciphertext, key, nonce)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
