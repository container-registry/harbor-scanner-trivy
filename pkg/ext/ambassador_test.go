package ext

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunCmdKeepsTheStreamsApart(t *testing.T) {
	stdout, stderr, err := DefaultAmbassador.RunCmd(exec.Command("sh", "-c", "echo out; echo err >&2"))
	require.NoError(t, err)
	require.Equal(t, "out\n", string(stdout))
	require.Equal(t, "err\n", string(stderr))
}

func TestRunCmdBoundsDiagnosticsAndKeepsTheirTail(t *testing.T) {
	// More stderr than the adapter is willing to hold.
	script := "head -c " + strconv.Itoa(2*MaxStderr) + " /dev/zero | tr '\\0' 'x' >&2; echo LAST >&2; exit 1"
	_, stderr, err := DefaultAmbassador.RunCmd(exec.Command("sh", "-c", script))
	require.Error(t, err)
	require.Len(t, stderr, MaxStderr)
	require.True(t, strings.HasSuffix(string(stderr), "LAST\n"))
}

func TestLimitedBufferReportsTruncation(t *testing.T) {
	b := &LimitedBuffer{Limit: 8}
	written, err := b.Write([]byte("abcd"))
	require.NoError(t, err)
	require.Equal(t, 4, written)
	require.False(t, b.Truncated())
	require.Equal(t, "abcd", b.String())

	written, err = b.Write([]byte("efghij"))
	require.NoError(t, err)
	// The writer is told everything was accepted; only the buffer is bounded.
	require.Equal(t, 6, written)
	require.True(t, b.Truncated())
	require.Equal(t, "cdefghij", b.String())

	require.NoError(t, func() error { _, err := b.Write([]byte("0123456789")); return err }())
	require.Equal(t, "23456789", b.String())
}

func TestLimitedBufferKeepsNothingForAnImpossibleLimit(t *testing.T) {
	// A negative limit is a caller's mistake. Writing must still not fail, and
	// must not panic slicing past the end of p either.
	for _, limit := range []int{-1, 0} {
		b := &LimitedBuffer{Limit: limit}
		written, err := b.Write([]byte("abcd"))
		require.NoError(t, err)
		require.Equal(t, 4, written)
		require.Empty(t, b.Bytes())
		require.True(t, b.Truncated())
	}
}
