//go:build withblob

package squisher

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

// runPhase1CaptureGP runs Phase 1 only and captures the 128-byte GP output buffer.
// This is the ENCODED ciphertext (NOT standard AES).
func runPhase1CaptureGP(payload [128]byte) ([128]byte, [20]byte) {
	mem := make([]byte, fpCompiledMemSize)
	copy(mem, cachedInitialMem)
	copy(mem[addrToOff(fpPayloadVAddr):], payload[:])

	xr := cachedInitialRegs
	sp := cachedInitialSP
	var vreg [32][2]uint64
	var nz, zz, cz, vz bool
	seenPages := make(map[uint64]bool)

	for i := 0; i < fpSplitIndex && i < len(cachedTrace); i++ {
		te := cachedTrace[i]
		if te.inst == 0xFFFFFFFF && te.stubRegs != nil {
			xr = *te.stubRegs
			sp = te.stubSP
			for addr, data := range te.stubNewPages {
				if !seenPages[addr] {
					off := addrToOff(addr)
					copy(mem[off:off+len(data)], data)
					seenPages[addr] = true
				}
			}
			continue
		}
		if te.inst == 0xD4200000 {
			continue
		}
		execCompiledInstr(mem, &xr, &sp, &vreg, &nz, &zz, &cz, &vz, te.inst, te.pc)
	}

	// Capture the GP output buffer (128 bytes at offset 16848)
	var gpOut [128]byte
	copy(gpOut[:], mem[16848:16848+128])

	// Also run Phase 2 to get the final hash
	for _, ci := range phase2InstrStream {
		execCompiledInstr(mem, &xr, &sp, &vreg, &nz, &zz, &cz, &vz, ci.inst, ci.pc)
	}

	outPtrOff := addrToOff(fpOutputVAddr)
	outAddr := binary.LittleEndian.Uint64(mem[outPtrOff:])
	outLenVAddr := cachedInitialRegs[6]
	outLenOff := addrToOff(outLenVAddr)
	outLen := binary.LittleEndian.Uint32(mem[outLenOff:])

	var hash [20]byte
	if outLen >= 164 && outAddr != 0 {
		off := addrToOff(outAddr)
		copy(hash[:], mem[off+144:off+164])
	}

	return gpOut, hash
}

// TestOutputEncodingPerByte checks if the WB-AES output encoding is per-byte.
// If changing one input byte only affects one output byte, the encoding
// decomposes into 16 independent 8→8 lookup tables.
func TestOutputEncodingPerByte(t *testing.T) {
	t.Log("=== Testing if WB-AES output encoding is per-byte ===")

	buildCachedTrace()
	buildCleanInstrStream()
	loadEmbeddedSnapshot()

	// Baseline: all zeros
	var zero [128]byte
	gpZero, _ := runPhase1CaptureGP(zero)
	t.Logf("GP(zeros) block 0: %x", gpZero[:16])
	t.Logf("GP(zeros) block 7: %x", gpZero[112:128])

	// For each input byte in block 0, flip it and see how many GP bytes change
	t.Log("\n--- Flipping each byte of block 0, counting GP output byte changes ---")

	for inputByte := 0; inputByte < 16; inputByte++ {
		var pay [128]byte
		pay[inputByte] = 0x01

		gpDelta, _ := runPhase1CaptureGP(pay)

		// Count how many bytes differ in block 0 of GP output
		block0Changes := 0
		otherChanges := 0
		changedPositions := []int{}

		for j := 0; j < 16; j++ {
			if gpDelta[j] != gpZero[j] {
				block0Changes++
				changedPositions = append(changedPositions, j)
			}
		}
		for j := 16; j < 128; j++ {
			if gpDelta[j] != gpZero[j] {
				otherChanges++
			}
		}

		indicator := "❌"
		if block0Changes == 1 {
			indicator = "✅ PER-BYTE"
		} else if block0Changes <= 4 {
			indicator = "🔶 SMALL SPREAD"
		}

		t.Logf("  Input byte %2d → %2d GP bytes change in block 0, %d in other blocks %s (positions: %v)",
			inputByte, block0Changes, otherChanges, indicator, changedPositions)
	}

	// Also test with value 0xFF (to check all bits)
	t.Log("\n--- Same test with value 0xFF ---")
	for inputByte := 0; inputByte < 16; inputByte++ {
		var pay [128]byte
		pay[inputByte] = 0xFF

		gpDelta, _ := runPhase1CaptureGP(pay)

		block0Changes := 0
		for j := 0; j < 16; j++ {
			if gpDelta[j] != gpZero[j] {
				block0Changes++
			}
		}
		otherChanges := 0
		for j := 16; j < 128; j++ {
			if gpDelta[j] != gpZero[j] {
				otherChanges++
			}
		}

		t.Logf("  Input byte %2d (0xFF) → %2d GP bytes change in block 0, %d in other blocks",
			inputByte, block0Changes, otherChanges)
	}
}

// TestExtractOutputEncoding attempts to extract the per-byte output encoding
// for block 7 (the first block processed, which has no carry-forward state).
// If the encoding is per-byte, we can build a 256-entry lookup table per position.
func TestExtractOutputEncoding(t *testing.T) {
	fmt.Println("=== Extracting output encoding for block 7 ===")
	
	buildCachedTrace()
	buildCleanInstrStream()
	loadEmbeddedSnapshot()

	keyHex := "c251c048e6a027945e178067df8ae466"
	key, _ := hex.DecodeString(keyHex)
	aesBlock, _ := aes.NewCipher(key)

	var gpOuts [256][16]byte
	var stdCTs [256][16]byte

	fmt.Println("Starting to probe 256 payloads...")
	for v := 0; v < 256; v++ {
		var pay [128]byte
		pay[112] = byte(v)

		aesBlock.Encrypt(stdCTs[v][:], pay[112:128])

		// Use the safe emulator run function
		gp, _ := runPhase1CaptureGP(pay)
		copy(gpOuts[v][:], gp[112:128])

		if v%10 == 0 {
			fmt.Printf("  [%d/256] probes complete\n", v)
		}
	}
	fmt.Println("Probes complete. Analyzing cross-byte coupling...")

	for srcPos := 0; srcPos < 4; srcPos++ {
		coupledTo := []int{}
		for dstPos := 0; dstPos < 16; dstPos++ {
			if dstPos == srcPos {
				continue
			}
			dstValues := make(map[byte]bool)
			for v := 0; v < 256; v++ {
				dstValues[gpOuts[v][dstPos]] = true
			}
			if len(dstValues) > 1 {
				coupledTo = append(coupledTo, dstPos)
			}
		}
		if len(coupledTo) == 0 {
			fmt.Printf("Varying input byte 0 at block 7: byte %d is INDEPENDENT (no coupling)\n", srcPos)
		} else {
			fmt.Printf("Varying input byte 0 at block 7: byte %d couples to %d other bytes %v\n",
				srcPos, len(coupledTo), coupledTo)
		}
	}
	_ = rand.Read
}
