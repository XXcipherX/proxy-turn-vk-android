package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestRTPMaskingPCAPProfileRegression checks the RTP fields and distributions
// that are visible to a passive observer in a packet capture. Wide statistical
// bounds make the test stable while still catching deterministic fingerprints.
func TestRTPMaskingPCAPProfileRegression(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, wrapKeyLen)
	payload := bytes.Repeat([]byte{0xa5}, 120)
	config := NewObfsConfig()
	state := NewObfsState()

	const samples = 4096
	markerCount := 0
	paddingCount := 0
	sequenceGapCount := 0
	lengths := make(map[int]struct{})
	var previousSequence uint16
	var previousTimestamp uint32
	var expectedSSRC uint32

	for sample := 0; sample < samples; sample++ {
		wire, err := obfsWrapPacket(key, payload, config, state)
		if err != nil {
			t.Fatalf("sample %d: wrap: %v", sample, err)
		}
		if !obfsIsRTPPacket(wire) || wire[0]>>6 != 2 || wire[1]&0x7f != 111 {
			t.Fatalf("sample %d: invalid RTP/Opus header %x", sample, wire[:12])
		}

		sequence := binary.BigEndian.Uint16(wire[2:4])
		timestamp := binary.BigEndian.Uint32(wire[4:8])
		ssrc := binary.BigEndian.Uint32(wire[8:12])
		if sample == 0 {
			expectedSSRC = ssrc
		} else {
			sequenceDelta := sequence - previousSequence
			if sequenceDelta < 1 || sequenceDelta > 3 {
				t.Fatalf("sample %d: sequence delta = %d", sample, sequenceDelta)
			}
			if sequenceDelta > 1 {
				sequenceGapCount++
			}
			timestampDelta := timestamp - previousTimestamp
			if timestampDelta < 120 || timestampDelta > 2880 {
				t.Fatalf("sample %d: timestamp delta = %d", sample, timestampDelta)
			}
		}
		if ssrc != expectedSSRC {
			t.Fatalf("sample %d: SSRC changed from %08x to %08x", sample, expectedSSRC, ssrc)
		}
		if wire[1]&0x80 != 0 {
			markerCount++
		}
		if wire[0]&0x20 != 0 {
			paddingCount++
			paddingLength := int(wire[len(wire)-1])
			if paddingLength < 1 || paddingLength > config.PaddingMax {
				t.Fatalf("sample %d: padding length = %d", sample, paddingLength)
			}
		}
		lengths[len(wire)] = struct{}{}

		plain := make([]byte, len(payload))
		n, err := obfsUnwrapPacket(key, wire, plain)
		if err != nil || !bytes.Equal(plain[:n], payload) {
			t.Fatalf("sample %d: unwrap mismatch: n=%d err=%v", sample, n, err)
		}
		previousSequence = sequence
		previousTimestamp = timestamp
	}

	if markerCount < 25 || markerCount > 110 {
		t.Fatalf("RTP marker count = %d, expected a sparse non-deterministic profile", markerCount)
	}
	if paddingCount < 900 || paddingCount > 1150 {
		t.Fatalf("RTP padding count = %d, expected approximately 25%%", paddingCount)
	}
	if sequenceGapCount < 8 || sequenceGapCount > 80 {
		t.Fatalf("sequence gap count = %d, expected occasional 2-3 increments", sequenceGapCount)
	}
	if len(lengths) < 12 {
		t.Fatalf("observed only %d packet lengths; padding profile became too deterministic", len(lengths))
	}
}
