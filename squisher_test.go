package squisher

import (
	"bytes"
	"testing"
)

func TestSquisherEngine(t *testing.T) {
	engine := NewEngine()
	
	// Feed 1KB of mock DCA trace data
	mockData := make([]byte, 1024)
	engine.FeedTrace(mockData)
	
	invariants, err := engine.Extract()
	if err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}
	
	if !bytes.Equal(invariants, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("Unexpected invariants extracted")
	}
}
