package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func loadWords(path string) (words []string) {
	words = make([]string, 0, 2048)

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}

	return words
}

func makeEntropy(entropyBits uint) []byte {
	entropy := make([]byte, entropyBits/8)

	_, err := rand.Read(entropy)
	if err != nil {
		log.Fatal(err)
	}

	return entropy
}

func computeChecksum(entropy []byte) *big.Int {
	var checksumBits uint = uint(len(entropy) / 4)

	hash := sha256.Sum256(entropy)

	checksum := new(big.Int).SetBytes(hash[:])
	// Right-shift until only checksumBits bits remains.
	checksum.Rsh(checksum, uint(len(hash)*8)-checksumBits)

	return checksum
}

func generateMnemonic(entropy []byte) string {
	entropyBits := uint(len(entropy) * 8)
	var checksumBits uint = entropyBits / 32
	var mnemonicLength = (entropyBits + checksumBits) / 11

	checksum := computeChecksum(entropy)

	// Concatenate entropy and checksum.
	bytes := new(big.Int).SetBytes(entropy)
	bytes.Lsh(bytes, checksumBits)
	bytes.Or(bytes, checksum)

	wordList := loadWords("english-wordlist.txt")

	mnemonic := make([]string, mnemonicLength)
	// We're taking bits from the right each time, so our loop has to fill
	// the array backwards.
	for i := int(mnemonicLength - 1); i >= 0; i-- {
		m := new(big.Int)
		bytes.DivMod(bytes, big.NewInt(2048), m)

		mnemonic[i] = wordList[m.Uint64()]
	}

	return strings.Join(mnemonic, " ")
}

func deriveSeed(mnemonic, password string) []byte {
	return pbkdf2.Key(
		[]byte(mnemonic),            // password
		[]byte("mnemonic"+password), // salt
		2048,                        // iterations
		64,                          // key length
		sha512.New)                  // hash function
}

func main() {
	mnemonic := generateMnemonic(makeEntropy(128))
	fmt.Printf("Mnemonic: %s\n", mnemonic)
	fmt.Printf("Derived seed: %0x\n", deriveSeed(mnemonic, ""))
}
