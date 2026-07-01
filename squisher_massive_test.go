//go:build withblob

package squisher

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// runPipelineFast runs the full Phase 1 + Phase 2 pipeline using
// the fastest available path. Returns the 20-byte hash.
func runPipelineFast(payload [128]byte) [20]byte {
	return FPCleanExchange(payload)
}

// aesECBMulti encrypts 128 bytes using AES-128-ECB with the known key.
func aesECBMulti(payload [128]byte) [128]byte {
	keyHex := "c251c048e6a027945e178067df8ae466"
	key, _ := hex.DecodeString(keyHex)
	block, _ := aes.NewCipher(key)
	var ct [128]byte
	for i := 0; i < 8; i++ {
		block.Encrypt(ct[i*16:(i+1)*16], payload[i*16:(i+1)*16])
	}
	return ct
}

// TestMassiveAffineTest runs hundreds of affine structure tests in parallel.
// If the full pipeline is affine, then for ANY inputs A, B:
//   f(A) XOR f(B) XOR f(A XOR B) XOR f(0) == 0
//
// We test this with random inputs to get high statistical confidence.
func TestMassiveAffineTest(t *testing.T) {
	loadEmbeddedSnapshot()
	buildCleanInstrStream()

	numTrials := 256
	workers := runtime.NumCPU()
	t.Logf("Running %d affine trials across %d CPU cores...", numTrials, workers)

	// Pre-compute f(0) once
	var zero [128]byte
	fZero := runPipelineFast(zero)
	t.Logf("f(0) = %x", fZero)

	// Generate random input pairs
	type trial struct {
		id   int
		payA [128]byte
		payB [128]byte
	}

	trials := make([]trial, numTrials)
	for i := 0; i < numTrials; i++ {
		var a, b [128]byte

		if i < 128 {
			// First 128 trials: single-byte canonical basis vectors
			a[i] = 0x01
			b[(i+64)%128] = 0x01
		} else {
			// Remaining: random inputs
			rand.Read(a[:])
			rand.Read(b[:])
		}
		trials[i] = trial{id: i, payA: a, payB: b}
	}

	// Results
	type result struct {
		id     int
		pass   bool
		check  [20]byte
		fA, fB, fC [20]byte
	}

	var passCount, failCount atomic.Int64
	results := make([]result, numTrials)
	completed := atomic.Int64{}

	start := time.Now()

	// Run trials in parallel
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for i := range trials {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			tr := trials[idx]

			// Compute f(A), f(B), f(A XOR B)
			fA := runPipelineFast(tr.payA)
			fB := runPipelineFast(tr.payB)

			var payC [128]byte
			for j := 0; j < 128; j++ {
				payC[j] = tr.payA[j] ^ tr.payB[j]
			}
			fC := runPipelineFast(payC)

			// Affine test: f(A) XOR f(B) XOR f(C) XOR f(0) should == 0
			var check [20]byte
			for j := 0; j < 20; j++ {
				check[j] = fA[j] ^ fB[j] ^ fC[j] ^ fZero[j]
			}

			isZero := true
			for _, b := range check {
				if b != 0 {
					isZero = false
					break
				}
			}

			if isZero {
				passCount.Add(1)
			} else {
				failCount.Add(1)
			}

			results[idx] = result{
				id: tr.id, pass: isZero, check: check,
				fA: fA, fB: fB, fC: fC,
			}

			done := completed.Add(1)
			if done%50 == 0 || done == int64(numTrials) {
				elapsed := time.Since(start)
				rate := float64(done*3) / elapsed.Seconds() // 3 pipeline runs per trial
				t.Logf("  [%d/%d] %.0f pipeline runs/sec, %d pass, %d fail",
					done, numTrials, rate, passCount.Load(), failCount.Load())
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("\n════════════════════════════════════════════")
	t.Logf("  AFFINE TEST RESULTS: %d trials in %v", numTrials, elapsed)
	t.Logf("  ✅ Pass (affine): %d", passCount.Load())
	t.Logf("  ❌ Fail (non-affine): %d", failCount.Load())
	t.Logf("  Pipeline runs/sec: %.0f", float64(numTrials*3)/elapsed.Seconds())
	t.Logf("════════════════════════════════════════════")

	if failCount.Load() == 0 {
		t.Log("\n🎉🎉🎉 ALL TRIALS PASS! THE FULL PIPELINE IS AFFINE!")
		t.Log("The squisher is AT MOST a GF(2) matrix + constant.")
		t.Log("Next: extract the 160×1024 binary matrix (128 basis vector runs).")
	} else {
		t.Log("\nFull pipeline is NOT affine. Showing first 5 failures:")
		shown := 0
		for _, r := range results {
			if !r.pass && shown < 5 {
				t.Logf("  Trial %d: check=%x", r.id, r.check)
				t.Logf("    f(A)=%x", r.fA)
				t.Logf("    f(B)=%x", r.fB)
				t.Logf("    f(C)=%x", r.fC)
				shown++
			}
		}
	}
}

// TestExtractGF2Matrix extracts the full GF(2) affine matrix.
// If the pipeline is affine: f(x) = M*x + c where c = f(0).
// M is a 160-bit × 1024-bit binary matrix (20 output bytes × 128 input bytes).
// Each column of M = f(e_i) XOR f(0), where e_i is the i-th basis vector.
func TestExtractGF2Matrix(t *testing.T) {
	loadEmbeddedSnapshot()
	buildCleanInstrStream()

	workers := runtime.NumCPU()
	t.Logf("Extracting GF(2) matrix using %d cores...", workers)

	// f(0) = the constant term
	var zero [128]byte
	fZero := runPipelineFast(zero)
	t.Logf("f(0) = %x (the affine constant)", fZero)

	// For each of 1024 input bits, compute the corresponding output column
	// 128 bytes × 8 bits = 1024 input bits
	// 20 bytes × 8 bits = 160 output bits
	numInputBits := 128 * 8
	matrix := make([][20]byte, numInputBits) // matrix[input_bit] = output_delta

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	completed := atomic.Int64{}
	start := time.Now()

	for bit := 0; bit < numInputBits; bit++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create input with single bit set
			var pay [128]byte
			pay[b/8] = 1 << (b % 8)

			fBit := runPipelineFast(pay)

			// Column = f(e_i) XOR f(0)
			var col [20]byte
			for j := 0; j < 20; j++ {
				col[j] = fBit[j] ^ fZero[j]
			}
			matrix[b] = col

			done := completed.Add(1)
			if done%100 == 0 || done == int64(numInputBits) {
				elapsed := time.Since(start)
				rate := float64(done) / elapsed.Seconds()
				t.Logf("  [%d/%d bits] %.0f bits/sec", done, numInputBits, rate)
			}
		}(bit)
	}

	wg.Wait()
	elapsed := time.Since(start)
	t.Logf("Matrix extracted in %v (%.0f bits/sec)", elapsed, float64(numInputBits)/elapsed.Seconds())

	// Verify: compute f(test_input) using the matrix and compare
	t.Log("\n=== Verifying matrix against 10 random inputs ===")
	verifyPass := 0
	for trial := 0; trial < 10; trial++ {
		var pay [128]byte
		rand.Read(pay[:])

		// Matrix prediction: result = f(0) XOR (XOR of all matrix[bit] where input bit is set)
		var predicted [20]byte
		copy(predicted[:], fZero[:])
		for bit := 0; bit < numInputBits; bit++ {
			byteIdx := bit / 8
			bitIdx := uint(bit % 8)
			if (pay[byteIdx]>>bitIdx)&1 == 1 {
				for j := 0; j < 20; j++ {
					predicted[j] ^= matrix[bit][j]
				}
			}
		}

		actual := runPipelineFast(pay)

		if predicted == actual {
			verifyPass++
			t.Logf("  Trial %d: ✅ MATCH (predicted == actual)", trial)
		} else {
			t.Logf("  Trial %d: ❌ MISMATCH", trial)
			t.Logf("    predicted: %x", predicted)
			t.Logf("    actual:    %x", actual)
			// Count differing bits
			diffBits := 0
			for j := 0; j < 20; j++ {
				d := predicted[j] ^ actual[j]
				for d != 0 {
					diffBits++
					d &= d - 1
				}
			}
			t.Logf("    differing bits: %d/160", diffBits)
		}
	}

	t.Logf("\n=== Matrix Verification: %d/10 pass ===", verifyPass)
	if verifyPass == 10 {
		t.Log("🎉🎉🎉 MATRIX IS CORRECT! The entire pipeline is a 160×1024 GF(2) matrix!")
		t.Log("The 353K-instruction squisher can be replaced with 20 lines of Go!")

		// Print the matrix in a compact format
		t.Log("\n=== Matrix (hex, one column per input byte) ===")
		for byteIdx := 0; byteIdx < 128; byteIdx++ {
			// XOR all 8 bit columns for this byte to get the byte-level effect
			// (This is just for visualization; the real matrix is bit-level)
			var byteEffect [20]byte
			for bit := 0; bit < 8; bit++ {
				col := matrix[byteIdx*8+bit]
				for j := 0; j < 20; j++ {
					byteEffect[j] |= col[j]
				}
			}
			nonzero := 0
			for _, b := range byteEffect {
				if b != 0 {
					nonzero++
				}
			}
			if byteIdx < 16 || byteIdx%16 == 0 {
				t.Logf("  Input byte %3d affects %2d/20 output bytes", byteIdx, nonzero)
			}
		}
	}

	_ = fmt.Sprint // suppress unused import
}
