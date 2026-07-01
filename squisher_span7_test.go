//go:build withblob

package squisher

import (
	"encoding/binary"
	"testing"
)

// TestTraceSpan7BlockBoundaries runs Phase 1 and captures the 20-byte
// span7 state at each block boundary. This reveals the fold structure:
// how each block transforms the carry-forward state.
func TestTraceSpan7BlockBoundaries(t *testing.T) {
	t.Log("=== Tracing span7 (20-byte state) at block boundaries ===")

	buildCachedTrace()
	buildCleanInstrStream()
	loadEmbeddedSnapshot()

	// First, find where span7 lives in memory.
	// The final 20-byte output is read from mem[off+144:off+164] where
	// off = addrToOff(outAddr) and outAddr is at fpOutputVAddr.
	// Let's run Phase 1 and find the actual span7 memory offset.

	var payload [128]byte
	mem := make([]byte, fpCompiledMemSize)
	copy(mem, cachedInitialMem)
	copy(mem[addrToOff(fpPayloadVAddr):], payload[:])

	xr := cachedInitialRegs
	sp := cachedInitialSP
	var vreg [32][2]uint64
	var nz, zz, cz, vz bool
	seenPages := make(map[uint64]bool)

	// We need to find the span7 address. Let's read it from the output pointer
	// structure. First run everything to find it.
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

	// Also run Phase 2 to populate the output pointer
	for _, ci := range phase2InstrStream {
		execCompiledInstr(mem, &xr, &sp, &vreg, &nz, &zz, &cz, &vz, ci.inst, ci.pc)
	}

	outPtrOff := addrToOff(fpOutputVAddr)
	outAddr := binary.LittleEndian.Uint64(mem[outPtrOff:])
	span7Off := addrToOff(outAddr) + 144
	t.Logf("Span7 memory offset: %d (0x%x)", span7Off, span7Off)
	t.Logf("Span7 after full run: %x", mem[span7Off:span7Off+20])

	// Now run Phase 1 again with SNAPSHOTS at regular intervals
	// We'll take a snapshot every ~207K instructions (roughly per-block boundary)
	t.Log("\n=== Running Phase 1 with periodic span7 snapshots ===")

	// Reset state
	mem2 := make([]byte, fpCompiledMemSize)
	copy(mem2, cachedInitialMem)
	copy(mem2[addrToOff(fpPayloadVAddr):], payload[:])
	xr2 := cachedInitialRegs
	sp2 := cachedInitialSP
	var vreg2 [32][2]uint64
	var nz2, zz2, cz2, vz2 bool
	seenPages2 := make(map[uint64]bool)

	// Take snapshots at regular intervals
	blockSize := fpSplitIndex / 8 // approximately per-block
	lastSnap := make([]byte, 20)
	copy(lastSnap, mem2[span7Off:span7Off+20])
	t.Logf("  Before execution: span7 = %x", lastSnap)

	for i := 0; i < fpSplitIndex && i < len(cachedTrace); i++ {
		te := cachedTrace[i]
		if te.inst == 0xFFFFFFFF && te.stubRegs != nil {
			xr2 = *te.stubRegs
			sp2 = te.stubSP
			for addr, data := range te.stubNewPages {
				if !seenPages2[addr] {
					off := addrToOff(addr)
					copy(mem2[off:off+len(data)], data)
					seenPages2[addr] = true
				}
			}
			continue
		}
		if te.inst == 0xD4200000 {
			continue
		}
		execCompiledInstr(mem2, &xr2, &sp2, &vreg2, &nz2, &zz2, &cz2, &vz2, te.inst, te.pc)

		// Snapshot at block boundaries
		if (i+1)%blockSize == 0 {
			blockNum := (i + 1) / blockSize
			snap := make([]byte, 20)
			copy(snap, mem2[span7Off:span7Off+20])

			changed := 0
			for j := 0; j < 20; j++ {
				if snap[j] != lastSnap[j] {
					changed++
				}
			}

			t.Logf("  After ~block %d (instr %d): span7 = %x (%d bytes changed)",
				blockNum, i+1, snap, changed)
			copy(lastSnap, snap)
		}
	}

	// Final state
	finalSnap := make([]byte, 20)
	copy(finalSnap, mem2[span7Off:span7Off+20])
	t.Logf("  Final span7: %x", finalSnap)

	// Now test with a DIFFERENT payload and compare
	t.Log("\n=== Comparing span7 evolution: zeros vs. payload[0]=0x01 ===")

	var pay2 [128]byte
	pay2[0] = 0x01

	mem3 := make([]byte, fpCompiledMemSize)
	copy(mem3, cachedInitialMem)
	copy(mem3[addrToOff(fpPayloadVAddr):], pay2[:])
	xr3 := cachedInitialRegs
	sp3 := cachedInitialSP
	var vreg3 [32][2]uint64
	var nz3, zz3, cz3, vz3 bool
	seenPages3 := make(map[uint64]bool)

	for i := 0; i < fpSplitIndex && i < len(cachedTrace); i++ {
		te := cachedTrace[i]
		if te.inst == 0xFFFFFFFF && te.stubRegs != nil {
			xr3 = *te.stubRegs
			sp3 = te.stubSP
			for addr, data := range te.stubNewPages {
				if !seenPages3[addr] {
					off := addrToOff(addr)
					copy(mem3[off:off+len(data)], data)
					seenPages3[addr] = true
				}
			}
			continue
		}
		if te.inst == 0xD4200000 {
			continue
		}
		execCompiledInstr(mem3, &xr3, &sp3, &vreg3, &nz3, &zz3, &cz3, &vz3, te.inst, te.pc)

		if (i+1)%blockSize == 0 {
			blockNum := (i + 1) / blockSize
			snap0 := mem2[span7Off : span7Off+20]
			snap1 := mem3[span7Off : span7Off+20]

			diffBytes := 0
			for j := 0; j < 20; j++ {
				if snap0[j] != snap1[j] {
					diffBytes++
				}
			}

			if diffBytes > 0 {
				t.Logf("  Block %d: %d/20 span7 bytes differ (zeros=%x, pay01=%x)",
					blockNum, diffBytes, snap0, snap1)
			} else {
				t.Logf("  Block %d: span7 IDENTICAL (block not yet affected)", blockNum)
			}
		}
	}

	t.Log("\n=== Key question: at which block does the input payload FIRST affect span7? ===")
	t.Log("If payload[0] only affects block 0 (processed LAST), divergence should appear late.")
}
