package proto

// ReplayWindowWords is the size of the replay window in 64-bit words.
// 32 words x 64 bits = a 2048-bit sliding window.
const ReplayWindowWords = 32

const replayWindowBits = ReplayWindowWords * 64

// ReplayWindow is a 2048-bit sliding-window replay filter (the WireGuard /
// IPsec anti-replay algorithm). The zero value is ready to use: sequence
// numbers start at 0, exactly like a freshly keyed sender.
//
// word[0] is the least-significant word: bit 0 means "Highest", bit k means
// "Highest-k". A ReplayWindow is not safe for concurrent use; callers
// serialise access (the session mutex).
type ReplayWindow struct {
	Highest uint64
	Window  [ReplayWindowWords]uint64
}

// Reset clears the window, as done when a session is (re)keyed.
func (r *ReplayWindow) Reset() { *r = ReplayWindow{} }

// Check records seq and reports whether it is acceptable: true if seq is new,
// false if it is a duplicate or older than the window.
func (r *ReplayWindow) Check(seq uint64) bool {
	if seq > r.Highest {
		diff := seq - r.Highest
		if diff >= replayWindowBits {
			r.Window = [ReplayWindowWords]uint64{}
		} else {
			wn := int(diff / 64)
			bn := uint(diff % 64)
			for i := ReplayWindowWords - 1; i >= 0; i-- {
				loSrc := i - wn
				hiSrc := loSrc - 1
				var lo, hi uint64
				if loSrc >= 0 {
					lo = r.Window[loSrc]
				}
				if bn > 0 && hiSrc >= 0 {
					hi = r.Window[hiSrc]
				}
				if bn > 0 {
					r.Window[i] = (lo << bn) | (hi >> (64 - bn))
				} else {
					r.Window[i] = lo
				}
			}
		}
		r.Window[0] |= 1
		r.Highest = seq
		return true
	}
	diff := r.Highest - seq
	if diff >= replayWindowBits {
		return false
	}
	word, bit := diff/64, diff%64
	if r.Window[word]&(1<<bit) != 0 {
		return false
	}
	r.Window[word] |= 1 << bit
	return true
}
