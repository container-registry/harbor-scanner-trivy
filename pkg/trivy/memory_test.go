package trivy

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func cgroupFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "memory.max")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestChildGoMemLimitDerivesEightyPercentOfTheCgroupLimit(t *testing.T) {
	limit := childGoMemLimit("", cgroupFile(t, "2147483648\n"))
	require.Equal(t, strconv.Itoa(2147483648*4/5), limit)
}

func TestChildGoMemLimitIsUnsetWithoutAFiniteCgroupLimit(t *testing.T) {
	for _, content := range []string{"max", "9223372036854771712", "0", "-1", "not a number", ""} {
		require.Empty(t, childGoMemLimit("", cgroupFile(t, content)), content)
	}
	require.Empty(t, childGoMemLimit("", filepath.Join(t.TempDir(), "absent")))
}

func TestChildGoMemLimitFallsBackToTheSecondCgroupPath(t *testing.T) {
	v1 := cgroupFile(t, "1000000000")
	require.Equal(t, "800000000", childGoMemLimit("", filepath.Join(t.TempDir(), "absent"), v1))
}

func TestUnlimitedV2EndsTheSearch(t *testing.T) {
	// A v1 path survives on a v2 host through the hybrid hierarchy, holding a
	// number nothing enforces. The file that answered first is the authority.
	v2, v1 := cgroupFile(t, "max"), cgroupFile(t, "1000000000")
	require.Empty(t, childGoMemLimit("", v2, v1))
	require.Equal(t, "800000000", childGoMemLimit("", filepath.Join(t.TempDir(), "absent"), v1))
}

func TestChildGoMemLimitHonoursExplicitSettings(t *testing.T) {
	require.Empty(t, childGoMemLimit("off", cgroupFile(t, "2147483648")))
	require.Equal(t, "2GiB", childGoMemLimit("2GiB", cgroupFile(t, "2147483648")))
}

// Verified against the runtime: GOMEMLIMIT=10GB, 1.5GiB or " 2GiB" makes a Go
// child print the value and exit 2 before main runs, so passing a configured
// value through unchecked would fail every scan.
func TestInvalidChildGoMemLimitFallsBackToTheCgroup(t *testing.T) {
	limit := filepath.Join(t.TempDir(), "memory.max")
	require.NoError(t, os.WriteFile(limit, []byte("1000000000\n"), 0o600))

	for _, configured := range []string{"10GB", "1.5GiB", " 2GiB", "2 GiB", "2gib", "abc"} {
		t.Run(configured, func(t *testing.T) {
			require.Equal(t, "800000000", childGoMemLimit(configured, limit))
		})
	}

	// With no cgroup to fall back to, the child keeps the runtime default
	// rather than being handed something that stops it starting.
	for _, configured := range []string{"10GB", "1.5GiB"} {
		require.Empty(t, childGoMemLimit(configured, filepath.Join(t.TempDir(), "absent")))
	}
}

func TestValidChildGoMemLimitIsPassedThrough(t *testing.T) {
	for _, configured := range []string{"2GiB", "800000000", "512MiB", "1TiB", "1024B", "16KiB"} {
		t.Run(configured, func(t *testing.T) {
			require.Equal(t, configured, childGoMemLimit(configured, filepath.Join(t.TempDir(), "absent")))
		})
	}
}

// Also measured against the runtime: these pass the syntax and overflow the
// int64 the limit is held in, and the child exits 2 before main runs.
func TestOverflowingChildGoMemLimitIsRejected(t *testing.T) {
	limit := filepath.Join(t.TempDir(), "memory.max")
	require.NoError(t, os.WriteFile(limit, []byte("1000000000\n"), 0o600))
	for _, configured := range []string{
		"9223372036854775808",  // 2^63, one past the maximum
		"18446744073709551615", // uint64 max
		"99999999999TiB",
		"9007199254740992KiB",
		"99999999999999999999999999", // more digits than a uint64 holds
	} {
		t.Run(configured, func(t *testing.T) {
			require.False(t, validGoMemLimit(configured))
			require.Equal(t, "800000000", childGoMemLimit(configured, limit))
		})
	}
	// The largest value the runtime does accept stays accepted.
	require.True(t, validGoMemLimit("9223372036854775807"))
	require.True(t, validGoMemLimit("8388607TiB"))
	require.False(t, validGoMemLimit("8388608TiB"))
}

func TestCgroupLimitResolvedThroughProcSelfCgroup(t *testing.T) {
	// A host cgroup namespace: the fixed path is the hierarchy root and says
	// "max", while this process's own cgroup carries the real limit.
	mount := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(mount, "memory.max"), []byte("max\n"), 0o600))
	own := filepath.Join(mount, "kubepods", "pod123", "container")
	require.NoError(t, os.MkdirAll(own, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(own, "memory.max"), []byte("2000000000\n"), 0o600))

	proc := filepath.Join(t.TempDir(), "cgroup")
	require.NoError(t, os.WriteFile(proc, []byte("0::/kubepods/pod123/container\n"), 0o600))

	paths := processCgroupMemoryPaths(proc, mount)
	require.Equal(t, []string{filepath.Join(own, "memory.max")}, paths)
	limit, ok := readCgroupMemoryLimit(paths)
	require.True(t, ok)
	require.EqualValues(t, 2000000000, limit)
}

func TestProcSelfCgroupIgnoresRootAndUnusableLines(t *testing.T) {
	mount := t.TempDir()
	proc := filepath.Join(t.TempDir(), "cgroup")
	require.NoError(t, os.WriteFile(proc, []byte("0::/\n12:cpu:/some/path\n"), 0o600))
	require.Empty(t, processCgroupMemoryPaths(proc, mount))

	// A v1 memory controller line resolves under the memory hierarchy.
	require.NoError(t, os.WriteFile(proc, []byte("7:memory:/kubepods/x\n"), 0o600))
	require.Equal(t,
		[]string{filepath.Join(mount, "memory", "kubepods", "x", "memory.limit_in_bytes")},
		processCgroupMemoryPaths(proc, mount))

	require.Empty(t, processCgroupMemoryPaths(filepath.Join(t.TempDir(), "absent"), mount))
}
