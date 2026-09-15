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
	if len(p) > b.Limit {
		p = p[len(p)-b.Limit:]
		b.truncated = true
	}
	if drop := len(b.buf) + len(p) - b.Limit; drop > 0 {
		b.buf = append(b.buf[:0], b.buf[drop:]...)
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	return written, nil
}

func (b *LimitedBuffer) Bytes() []byte { return b.buf }

func (b *LimitedBuffer) String() string { return string(b.buf) }

// Truncated reports whether output was dropped, so callers that parse the
// bytes can reject them instead of failing on a partial document.
func (b *LimitedBuffer) Truncated() bool { return b.truncated }
