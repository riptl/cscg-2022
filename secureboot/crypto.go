package main

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/bits"
	"os"
)

var (
	doPatch   bool
	doSign    bool
	doSample  bool
	doLeak    bool
	doRecover bool

	bootloaderPath string
	targetPath     string
	verbosity      int
	leakByte       uint
	hexLeakSuffix  string
	hexHash        string
)

const keyIdxLow = 0xed
const keyIdxHigh = 0xed + 8

func main() {
	flag.StringVar(&bootloaderPath, "bootloader", "", "Path to bootloader disk image")
	flag.StringVar(&targetPath, "target", "", "Path to target disk image")
	flag.IntVar(&verbosity, "v", 0, "Verbosity level (0-4)")
	flag.BoolVar(&doPatch, "patch", false, "Patch target with fake signature")
	flag.BoolVar(&doSign, "sign", false, "Sign mode")
	flag.BoolVar(&doSample, "sample", false, "Sample mode")
	flag.BoolVar(&doLeak, "leak", false, "Mine for hash side-channel leak")
	flag.UintVar(&leakByte, "leak-index", keyIdxLow, "Index of byte to leak")
	flag.BoolVar(&doRecover, "recover", false, "Recover leaked byte")
	flag.StringVar(&hexLeakSuffix, "leak-nonce", "", "Nonce generated by leak command")
	flag.StringVar(&hexHash, "hash", "", "Expected hash")
	flag.Parse()

	switch {
	case doSign, doPatch:
		sign()
	case doSample:
		sample()
	case doLeak:
		leak()
	case doRecover:
		recover_()
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func sign() {
	if bootloaderPath == "" || targetPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	loader, _, err := loadMBR(bootloaderPath)
	if err != nil {
		log.Fatal(err)
	}
	data, providedSig, err := loadMBR(targetPath)
	if err != nil {
		log.Fatal(err)
	}

	hasher := bootHasher{
		loader:    &loader,
		verbosity: verbosity,
	}

	hash := hasher.Sum(data[:])
	fmt.Printf("Image hash:      %x\n", hash[:])
	fmt.Printf("Image signature: %x\n", providedSig[:])

	expectedHash := providedSig
	key := keyFromLoader(&loader)
	decrypt8(&loader, &expectedHash, &key, verbosity >= 1)
	fmt.Printf("Expected hash:   %x\n", expectedHash[:])

	if subtle.ConstantTimeCompare(hash[:], expectedHash[:]) == 1 {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL")
	}

	fakeSig := hash
	encrypt8(&loader, &fakeSig, &key, verbosity >= 1)
	fmt.Printf("Fake signature:  %x\n", fakeSig[:])

	if doPatch {
		if err := patchSig(targetPath, fakeSig); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Patched signature")
	}
}

func sample() {
	if bootloaderPath == "" || targetPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	loader, _, err := loadMBR(bootloaderPath)
	if err != nil {
		log.Fatal(err)
	}
	data, _, err := loadMBR(targetPath)
	if err != nil {
		log.Fatal(err)
	}
	hasher := bootHasher{
		loader:    &loader,
		verbosity: verbosity,
	}
	_ = hasher.Sum(data[:])

	printSampling(&hasher.sampling)
}

func leak() {
	if bootloaderPath == "" {
		flag.Usage()
		os.Exit(1)
	}
	loader, _, err := loadMBR(bootloaderPath)
	if err != nil {
		log.Fatal(err)
	}
	for i := keyIdxLow; i < keyIdxHigh; i++ {
		loader[i] = 0
	}

	// map "leaked byte value" => "best hash nonce"
	var nonces [256]leakScore
	getProgress := func() float32 {
		var prog uint
		for _, nonce := range nonces {
			if nonce.exist && len(nonce.deps) == 0 {
				prog++
			}
		}
		return 100 * (float32(prog) / 256)
	}

	var data [512]byte
	for i := range data {
		data[i] = 0xfc
	}
	for nonce := 0; nonce < 0x10000; nonce++ {
		fmt.Printf("Scanning %04x (%.1f%%)\n", nonce, getProgress())
		binary.BigEndian.PutUint16(data[510:512], uint16(nonce))
		for value := 0; value < 0x100; value++ {
			if nonces[value].exist && len(nonces[value].deps) == 0 {
				continue
			}

			loader[leakByte] = uint8(value)
			hasher := bootHasher{
				loader:    &loader,
				verbosity: verbosity,
			}
			hash := hasher.Sum(data[:])
			if hash == [8]byte{} {
				continue
			}

			nonces[value].set(uint8(leakByte), uint8(value), uint16(nonce), &hasher.sampling, hash)
		}
	}
	for leakValue, score := range nonces {
		if !score.exist || len(score.deps) != 0 {
			continue
		}
		fmt.Printf("loader[%02x]=%02x nonce=%04x hash=%x\n", leakByte, leakValue, score.nonce, score.hash[:])
	}
}

type leakScore struct {
	exist bool
	deps  []uint8
	nonce uint16
	hash  [8]byte
}

func (l *leakScore) set(leakByte uint8, leakValue uint8, nonce uint16, sampling *[256]uint, hash [8]byte) {
	deps := make([]uint8, 0, 8)
	for k := uint8(keyIdxLow); k < uint8(keyIdxHigh); k++ {
		if k == uint8(leakByte) {
			if sampling[k] == 0 {
				return // not good, we want to leak that byte
			}
		} else if sampling[k] != 0 {
			deps = append(l.deps, k)
		}
	}
	if !l.exist || len(deps) < len(l.deps) {
		l.exist = true
		l.nonce = nonce
		l.deps = deps
		l.hash = hash
		if len(deps) == 0 {
			fmt.Printf("loader[%02x]=%02x nonce=%04x hash=%x\n", leakByte, leakValue, l.nonce, l.hash)
		}
	}
}

func recover_() {
	var hash [8]byte
	hashN, hashErr := hex.Decode(hash[:], []byte(hexHash))
	var nonce [8]byte
	nonceN, nonceErr := hex.Decode(nonce[:], []byte(hexLeakSuffix))
	if bootloaderPath == "" || hashN != 8 || hashErr != nil || nonceN != 8 || nonceErr != nil {
		flag.Usage()
		os.Exit(1)
	}
	loader, _, err := loadMBR(bootloaderPath)
	if err != nil {
		log.Fatal(err)
	}

	var data [512]byte
	for i := range data {
		data[i] = 0xfc
	}
	copy(data[504:512], nonce[:])
	for i := 0; i < len(data); i += 30 {
		line := data[i:]
		if len(line) > 30 {
			line = line[:30]
		}
		fmt.Println(hex.EncodeToString(line))
	}
	fmt.Println("0000000000000000EOF")
	for i := 0; i < 0x100; i++ {
		loader[leakByte] = uint8(i)
		hasher := bootHasher{
			loader: &loader,
		}
		actualHash := hasher.Sum(data[:])

		var xorHash [8]byte
		var bitCount uint
		for i := range actualHash {
			xorHash[i] = hash[i] ^ actualHash[i]
			bitCount += uint(bits.OnesCount8(xorHash[i]))
		}

		var deps []string
		for i := keyIdxLow; i < keyIdxHigh; i++ {
			if hasher.sampling[i] > 0 {
				deps = append(deps, fmt.Sprintf("%02x", i))
			}
		}

		fmt.Printf("Checking %02x: HASH=%x XOR=%x BITS=%3d DEPS=%v\n", i, actualHash[:], xorHash[:], bitCount, deps)

		if actualHash == hash {
			fmt.Printf("loader[%02x] = %02x\n", leakByte, i)
			return
		}
	}
	fmt.Println("Sorry, no match :(")
}

func loadMBR(filePath string) (mbr [512]byte, sig [8]byte, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return [512]byte{}, [8]byte{}, err
	}
	defer f.Close()

	_, err = io.ReadFull(f, mbr[:])
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	_, _ = io.ReadFull(f, sig[:])
	return
}

func patchSig(filePath string, sig [8]byte) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(0x200, 0); err != nil {
		return err
	}
	if _, err := f.Write(sig[:]); err != nil {
		return err
	}

	return nil
}

type bootHasher struct {
	loader    *[512]byte
	verbosity int
	sampling  [256]uint // reads from "loader"

	sig1 [8]byte
	sig2 [8]byte
}

func (h *bootHasher) Sum(b []byte) [8]byte {
	// 0629..066b
	for len(b) > 0 {
		// 065c..0669 (Read next block)
		var block [8]byte
		copy(block[:], b)
		if len(b) > 8 {
			b = b[8:]
		} else {
			b = nil
		}
		h.debugf(2, "  data: %x\n", block[:])
		// 0632..063c
		h.sig2 = h.sig1
		// 063c..0647
		h.debugf(2, "  pre_block: %x %x\n", h.sig1[:], h.sig2[:])
		h.block(block)
		// 0647..065c
		h.debugf(2, "  pre_xor: %x %x\n", h.sig1[:], h.sig2[:])
		for i := 0; i < 8; i++ {
			// 0650..065a
			h.sig1[i] = h.sig2[i] ^ h.sig1[i]
		}
		h.debugf(1, "block: %x %x\n", h.sig1[:], h.sig2[:])
	}
	return h.sig1
}

func (h *bootHasher) block(data [8]byte) {
	dx := uint16(0)
	al := h.sig1[0]
	for i := 0x100; i > 0; i-- {
		h.debugf(4, "      data[%02x] => %02x", dx, data[dx])
		al += data[dx]
		h.sampling[al]++
		h.debugf(4, "  loader[%02x] => %02x\n", al, h.loader[al])
		al = h.loader[al]
		dx = (dx + 1) % 8

		al += h.sig1[dx]
		al = bits.RotateLeft8(al, 1)
		h.sig1[dx] = al

		h.debugf(3, "    round %02d: %x\n", 0x100-i, h.sig1[:])
	}
}

func (b *bootHasher) debugf(v int, x string, args ...any) {
	if v <= b.verbosity {
		fmt.Printf(x, args...)
	}
}

// Function at 0x06c2
func decrypt8(loader *[512]byte, data *[8]byte, key *[8]byte, verbose bool) {
	for cx := uint16(0x100); cx > 0; cx-- {
		dx1 := (cx - 1) % 8
		dx2 := cx % 8
		data[dx2] = bits.RotateLeft8(data[dx2], 7) - loader[data[dx1]+key[dx1]]
		if verbose {
			fmt.Printf("  decrypt8 %3d: %x\n", cx, data[:])
		}
	}
}

// Inverse of decrypt8
func encrypt8(loader *[512]byte, data *[8]byte, key *[8]byte, verbose bool) {
	for cx := uint16(0); cx < 0x100; cx++ {
		dx2 := (cx + 1) % 8
		dx1 := cx % 8
		data[dx2] = bits.RotateLeft8(data[dx2]+loader[data[dx1]+key[dx1]], 1)
		if verbose {
			fmt.Printf("  encrypt8 %3d: %x\n", cx, data[:])
		}
	}
}

func printSampling(sampling *[256]uint) {
	for i, v := range sampling {
		fmt.Printf("  loader[%02x] = %4d\n", i, v)
	}
}

func keyFromLoader(loader *[512]byte) (out [8]byte) {
	copy(out[:], loader[keyIdxLow:keyIdxHigh])
	return
}
