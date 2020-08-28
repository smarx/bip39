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

	"github.com/ethereum/go-ethereum/crypto"
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

func isValid(mnemonic []string, checksumBits int, reverseWords map[string]int) bool {
	bytes := new(big.Int)

	for _, word := range mnemonic {
		bytes.Lsh(bytes, 11)
		bytes.Add(bytes, big.NewInt(int64(reverseWords[word])))
	}

	checksum := new(big.Int)
	bytes.DivMod(bytes, big.NewInt(2<<(checksumBits-1)), checksum)

	return checksum.Cmp(computeChecksum(bytes.Bytes())) == 0
}

func findPossibleSeeds(mnemonic []string, invalidWords []int, checksumBits int, wordList []string, reverseWords map[string]int) {
	if len(invalidWords) == 0 {
		if isValid(mnemonic, checksumBits, reverseWords) {
			seed := deriveSeed(strings.Join(mnemonic, " "), "")
			fmt.Printf("%0x -> %0x\n", seed, deriveAddress(seed))
		}
		return
	}

	for _, word := range wordList {
		mnemonic[invalidWords[0]] = word
		findPossibleSeeds(mnemonic, invalidWords[1:], checksumBits, wordList, reverseWords)
	}
}

func crack(mnemonicString string) {
	mnemonic := strings.Split(mnemonicString, " ")

	reverseWords := make(map[string]int)
	wordList := loadWords("english-wordlist.txt")
	for i, word := range wordList {
		reverseWords[word] = i
	}

	reverseChecksum := map[int]int{12: 4, 15: 5, 18: 6, 21: 7, 24: 8}
	checksumBits, ok := reverseChecksum[len(mnemonic)]
	if !ok {
		log.Fatal("Invalid number of words in the mnemonic.")
	}

	invalidWords := make([]int, 0)

	for i, word := range mnemonic {
		if _, ok := reverseWords[word]; !ok {
			invalidWords = append(invalidWords, i)
		}
	}

	findPossibleSeeds(mnemonic, invalidWords, checksumBits, wordList, reverseWords)
}

func deriveAddress(seed []byte) []byte {
	// just use the first 32 bytes of the seed as a private key
	privateKey, err := crypto.ToECDSA(seed[:32])
	if err != nil {
		log.Fatal(err)
	}
	return crypto.PubkeyToAddress(privateKey.PublicKey).Bytes()
}

func main() {
	if len(os.Args) == 1 {
		mnemonic := generateMnemonic(makeEntropy(128))
		fmt.Printf("Mnemonic: %s\n", mnemonic)
		seed := deriveSeed(mnemonic, "")
		fmt.Printf("Derived seed: %0x\n", seed)
		fmt.Printf("Derived address: %0x\n", deriveAddress(seed))
	} else {
		// join arguments to avoid having to quote mnemonic
		mnemonic := strings.Join(os.Args[1:], " ")
		crack(mnemonic)
	}
}
