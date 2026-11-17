package proto

import "testing"

func TestReplaySequentialAccepted(t *testing.T) {
	var w ReplayWindow
	for _, seq := range []uint64{1, 2, 3} {
		if !w.Check(seq) {
			t.Fatalf("seq %d rejected", seq)
		}
	}
	if w.Highest != 3 {
		t.Fatalf("highest=%d want 3", w.Highest)
	}
}

func TestReplayDuplicateRejected(t *testing.T) {
	var w ReplayWindow
	if !w.Check(5) {
		t.Fatal("first 5 rejected")
	}
	if w.Check(5) {
		t.Fatal("duplicate 5 accepted")
	}
}

func TestReplayFirstPacketSeqZero(t *testing.T) {
	// Senders start counting at 0, so the very first packet has seq 0.
	var w ReplayWindow
	if !w.Check(0) {
		t.Fatal("seq 0 rejected on a fresh window")
	}
	if w.Check(0) {
		t.Fatal("duplicate seq 0 accepted")
	}
	if !w.Check(1) {
		t.Fatal("seq 1 rejected after 0")
	}
}

func TestReplayOutOfOrderWithinWindow(t *testing.T) {
	var w ReplayWindow
	w.Check(100)
	if !w.Check(50) {
		t.Fatal("out-of-order 50 rejected")
	}
	if w.Check(50) {
		t.Fatal("duplicate out-of-order 50 accepted")
	}
}

func TestReplayTooOldRejected(t *testing.T) {
	var w ReplayWindow
	w.Check(3000)
	if w.Check(1) {
		t.Fatal("seq 1 accepted though far outside window")
	}
}

func TestReplayBoundaryJustInside(t *testing.T) {
	var w ReplayWindow
	w.Check(2048)
	// diff = 2047 < 2048: inside the window.
	if !w.Check(1) {
		t.Fatal("seq 1 rejected; diff 2047 is inside the window")
	}
}

func TestReplayBoundaryJustOutside(t *testing.T) {
	var w ReplayWindow
	w.Check(2048)
	// diff = 2048 == window size: too old.
	if w.Check(0) {
		t.Fatal("seq 0 accepted; diff 2048 is outside the window")
	}
}

func TestReplayLargeGapResetsWindow(t *testing.T) {
	var w ReplayWindow
	w.Check(1)
	if !w.Check(100000) {
		t.Fatal("large jump rejected")
	}
	if w.Highest != 100000 {
		t.Fatalf("highest=%d", w.Highest)
	}
	if w.Check(1) {
		t.Fatal("seq 1 accepted after large gap")
	}
}

func TestReplayWindowShiftsAcrossWordBoundaries(t *testing.T) {
	// Exercise shifts that are exact multiples of 64 and ones that straddle
	// word boundaries, then verify every earlier sequence is still remembered.
	for _, step := range []uint64{1, 63, 64, 65, 127, 128, 200, 1000} {
		var w ReplayWindow
		seqs := []uint64{10, 10 + step, 10 + 2*step}
		for _, s := range seqs {
			if !w.Check(s) {
				t.Fatalf("step=%d: first sight of %d rejected", step, s)
			}
		}
		for _, s := range seqs {
			if w.Highest-s < replayWindowBits && w.Check(s) {
				t.Fatalf("step=%d: replay of %d accepted", step, s)
			}
		}
	}
}

func TestReplayFillWindowThenReplayAll(t *testing.T) {
	var w ReplayWindow
	const n = 2048
	for s := uint64(1); s <= n; s++ {
		if !w.Check(s) {
			t.Fatalf("seq %d rejected", s)
		}
	}
	for s := uint64(1); s <= n; s++ {
		if w.Check(s) {
			t.Fatalf("replay of %d accepted", s)
		}
	}
}

func TestReplayReverseOrderWithinWindow(t *testing.T) {
	var w ReplayWindow
	w.Check(2000)
	for s := uint64(1999); s >= 1000; s-- {
		if !w.Check(s) {
			t.Fatalf("seq %d rejected", s)
		}
	}
	for s := uint64(1999); s >= 1000; s-- {
		if w.Check(s) {
			t.Fatalf("replay of %d accepted", s)
		}
	}
}

func TestReplayReset(t *testing.T) {
	var w ReplayWindow
	w.Check(10)
	w.Reset()
	if w.Highest != 0 || w.Window != [ReplayWindowWords]uint64{} {
		t.Fatal("Reset did not clear state")
	}
	if !w.Check(10) {
		t.Fatal("seq 10 rejected after Reset")
	}
}
