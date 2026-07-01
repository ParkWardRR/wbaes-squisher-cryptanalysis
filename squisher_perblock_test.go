//go:build withblob

package squisher

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// TestPerBlockEncodingEquivalence checks if different blocks use
// the same or different output encodings.
//
// Key observation from Experiment 4:
//   Block 0 GP output: 0f4a618dee81f55897b597d9f81f6fa2  (DIFFERENT)
//   Blocks 1-7 GP out: 284deaaccdb7eb224b289cc8ab4b06af  (ALL SAME)
//
// If blocks 1-7 use the same encoding, we can extract it once.
// Block 0 differs because it's processed last (different interleaving state).
func TestPerBlockEncodingEquivalence(t *testing.T) {
	t.Log("=== Testing if blocks use the same output encoding ===")

	keyHex := "c251c048e6a027945e178067df8ae466"
	key, _ := hex.DecodeString(keyHex)
	cipher, _ := aes.NewCipher(key)

	// Test 1: Put DIFFERENT data in each block, check if blocks with SAME
	// plaintext produce SAME GP output regardless of position.

	// Payload where block 1 = block 3 = 0x01 repeated, all others = 0x00
	var pay1 [128]byte
	for j := 16; j < 32; j++ {
		pay1[j] = 0x01 // block 1
	}
	for j := 48; j < 64; j++ {
		pay1[j] = 0x01 // block 3 (same data as block 1)
	}

	gp1, _ := runPhase1CaptureGP(pay1)

	t.Logf("Block 1 GP output: %x", gp1[16:32])
	t.Logf("Block 3 GP output: %x", gp1[48:64])

	block1Match := true
	for j := 0; j < 16; j++ {
		if gp1[16+j] != gp1[48+j] {
			block1Match = false
			break
		}
	}

	if block1Match {
		t.Log("✅ Block 1 == Block 3 (same plaintext → same GP output)")
		t.Log("   → Blocks 1-7 use the SAME output encoding!")
	} else {
		t.Log("❌ Block 1 ≠ Block 3 (same plaintext → DIFFERENT GP output)")
		t.Log("   → Each block has its OWN output encoding")
	}

	// Test 2: Does block 0 use a different encoding than block 1?
	var pay2 [128]byte
	for j := 0; j < 16; j++ {
		pay2[j] = 0x01 // block 0
	}
	for j := 16; j < 32; j++ {
		pay2[j] = 0x01 // block 1 (same data)
	}

	gp2, _ := runPhase1CaptureGP(pay2)

	t.Logf("\nBlock 0 GP output: %x", gp2[0:16])
	t.Logf("Block 1 GP output: %x", gp2[16:32])

	block0Match := true
	for j := 0; j < 16; j++ {
		if gp2[j] != gp2[16+j] {
			block0Match = false
			break
		}
	}

	if block0Match {
		t.Log("✅ Block 0 == Block 1 (same encoding)")
	} else {
		t.Log("❌ Block 0 ≠ Block 1 (different encoding)")
	}

	// Test 3: For blocks 1-7, build the encoding table.
	// Vary block 1's input through 256 values of byte 0.
	// The standard AES ciphertext is known (we have the key).
	// Mapping: AES(plaintext) → GP_output gives us OutEnc.
	t.Log("\n=== Extracting OutEnc for block 1 (256 probes on byte 0) ===")

	type encPair struct {
		stdCT  [16]byte
		gpOut  [16]byte
	}
	pairs := make([]encPair, 256)

	for v := 0; v < 256; v++ {
		var pay [128]byte
		pay[16] = byte(v) // byte 0 of block 1

		var stdCT [16]byte
		cipher.Encrypt(stdCT[:], pay[16:32])

		gp, _ := runPhase1CaptureGP(pay)

		pairs[v] = encPair{stdCT: stdCT}
		copy(pairs[v].gpOut[:], gp[16:32])
	}

	// Analyze byte-by-byte: for each byte position, how many unique GP values do we see?
	t.Log("\nPer-byte analysis of OutEnc(block 1):")
	for pos := 0; pos < 16; pos++ {
		uniqueGP := make(map[byte]bool)
		uniqueStd := make(map[byte]bool)
		for _, p := range pairs {
			uniqueGP[p.gpOut[pos]] = true
			uniqueStd[p.stdCT[pos]] = true
		}
		t.Logf("  Byte %2d: %3d unique std CT values, %3d unique GP values",
			pos, len(uniqueStd), len(uniqueGP))
	}

	// Check if the mapping is consistent: same stdCT → same gpOut?
	ctToGP := make(map[[16]byte][16]byte)
	consistent := true
	for _, p := range pairs {
		if existing, ok := ctToGP[p.stdCT]; ok {
			if existing != p.gpOut {
				consistent = false
				t.Logf("  ❌ INCONSISTENCY: same stdCT maps to different GP outputs!")
				break
			}
		}
		ctToGP[p.stdCT] = p.gpOut
	}

	if consistent {
		t.Log("\n✅ OutEnc is CONSISTENT: same standard CT always produces same GP output")
		t.Log("   → OutEnc is a deterministic function of the AES ciphertext")
		t.Log("   → We can build a lookup table or characterize it algebraically!")
	}

	// Check: is the full 16-byte output a bijection on 16-byte inputs?
	reverseMap := make(map[[16]byte]bool)
	for _, gp := range ctToGP {
		reverseMap[gp] = true
	}
	t.Logf("\n  %d unique stdCT → %d unique gpOut (%d unique stdCT inputs tested)",
		len(ctToGP), len(reverseMap), len(pairs))

	if len(reverseMap) == len(ctToGP) {
		t.Log("  ✅ OutEnc appears to be a BIJECTION (injective on tested inputs)")
	} else {
		t.Log("  ❌ OutEnc has COLLISIONS (not injective)")
	}
}
