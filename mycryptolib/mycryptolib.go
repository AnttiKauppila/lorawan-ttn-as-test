package mycryptolib

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
)

// AESEncrypt Flag telling Crypt() to go Encrypt mode
const AESEncrypt uint = 0

// AESDecrypt Flag telling Crypt() to go Decrypt mode
const AESDecrypt uint = 1

// Crypt encrypts or decrypts using AES128-ECB
func Crypt(flag uint, key, input, output []byte) {

	fmt.Printf("CRYPTO-Library flag: %T\n", flag)
	fmt.Printf("CRYPTO-Library key: %x\n", key)
	fmt.Printf("CRYPTO-Library input: %x\n", input)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//blockSize := 16

	for bs, be := 0, aes.BlockSize; bs < len(input); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		if flag == AESDecrypt {
			cipher.Decrypt(output[bs:be], input[bs:be])
		} else {
			cipher.Encrypt(output[bs:be], input[bs:be])
		}

	}

	fmt.Printf("CRYPTO-Library output: %s\n", hex.EncodeToString(output))
}
