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
