package main

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/bits"
	"os"
)

func main() {
	bootloaderPath := flag.String("bootloader", "", "Path to bootloader disk image")
	targetPath := flag.String("target", "", "Path to target disk image")
	verbosity := flag.Int("v", 0, "Verbosity level (0-4)")
	hexKey := flag.String("key", "4100410041004100", "Encryption key in hex")
	patch := flag.Bool("patch", false, "Patch target with fake signature")
	flag.Parse()
	var key [8]byte
	keyN, keyErr := hex.Decode(key[:], []byte(*hexKey))
	if *bootloaderPath == "" || *targetPath == "" || keyN != 8 || keyErr != nil {
		flag.Usage()
		os.Exit(1)
	}

	loader, _, err := loadMBR(*bootloaderPath)
	if err != nil {
		log.Fatal(err)
	}
	data, providedSig, err := loadMBR(*targetPath)
	if err != nil {
		log.Fatal(err)
	}

	hasher := bootHasher{
		loader:    &loader,
		verbosity: *verbosity,
	}

	hash := hasher.Sum(data[:])
	if *verbosity == 4 {
		// Dump data accesses to loader binary.
		fmt.Println("Sampling")
		for i, v := range hasher.sampling {
			fmt.Printf("  loader[%02x] = %4d\n", i, v)
		}
	}

	fmt.Printf("Image hash:      %x\n", hash[:])
	fmt.Printf("Image signature: %x\n", providedSig[:])

	expectedHash := providedSig
	decrypt8(&loader, &expectedHash, &key, *verbosity >= 1)
	fmt.Printf("Expected hash:   %x\n", expectedHash[:])

	if subtle.ConstantTimeCompare(hash[:], expectedHash[:]) == 1 {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL")
	}

	fakeSig := hash
	encrypt8(&loader, &fakeSig, &key, *verbosity >= 1)
	fmt.Printf("Fake signature:  %x\n", fakeSig[:])

	if *patch {
		if err := patchSig(*targetPath, fakeSig); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Patched signature")
	}
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

func (h *bootHasher) Reset() {
	h.sig1 = [8]byte{}
	h.sig2 = [8]byte{}
	h.sampling = [256]uint{}
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
		ah := data[dx]
		h.debugf(4, "      ax=%02x%02x (mov ah, byte [di])\n", ah, al)
		al += ah
		h.debugf(4, "      ax=%02x%02x (add al, ah)\n", ah, al)
		al = h.loader[al]
		h.sampling[al]++
		h.debugf(4, "      ax=%02x%02x (xlatb)\n", ah, al)
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
