package ext

const (
	// MaxStdout bounds output that is parsed, MaxStderr output that is only
	// logged or reported.
	MaxStdout = 1 << 20
	MaxStderr = 256 << 10
)

// LimitedBuffer bounds what a child process can make the adapter hold, even if
// a broken binary emits unbounded data. Writes never fail, because failing a
// diagnostic copy would mask the failure being diagnosed: the oldest bytes are
// dropped instead, keeping the tail where a command reports what went wrong.
type LimitedBuffer struct {
	Limit     int
	buf       []byte
	truncated bool
}

func (b *LimitedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	// A negative limit is a caller's mistake, not a reason to panic slicing p
	// below. Keeping nothing is the closest honest reading of it.
	if b.Limit < 0 {
		b.Limit = 0
	}
	if len(p) > b.Limit {
		p = p[len(p)-b.Limit:]
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.Limit {
		b.truncated = true
		// Trimming on every write would copy the whole retained tail each
		// time, so a child emitting a megabyte in small writes would cost the
		// adapter O(limit) per write. Let the buffer reach twice the limit and
		// trim then: amortized O(1) for at most twice the memory.
		if len(b.buf) > 2*b.Limit {
			b.trim()
		}
	}
	return written, nil
}

func (b *LimitedBuffer) trim() {
	if len(b.buf) > b.Limit {
		b.buf = append(b.buf[:0], b.buf[len(b.buf)-b.Limit:]...)
	}
}

// Bytes returns the retained tail. It trims first, because Write leaves room to
// spare rather than paying for it on every write; readers come after the child
// has exited, so this is not concurrent with writing.
func (b *LimitedBuffer) Bytes() []byte {
	b.trim()
	return b.buf
}

func (b *LimitedBuffer) String() string { return string(b.Bytes()) }

// Truncated reports whether output was dropped. It is a property of the buffer,
// available to code holding one directly; RunCmd returns bytes rather than the
// buffer, so a command's callers do not learn this and must not be written as
// though they could.
func (b *LimitedBuffer) Truncated() bool { return b.truncated }
