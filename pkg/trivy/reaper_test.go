package trivy

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/metrics"
)

// A pid above the usual maximum, so no process can hold it.
const deadPID = 2147483000

func tempDir(t *testing.T, root, name string, size int) string {
	t.Helper()
	path := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(filepath.Join(path, "fanal"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(path, "fanal", "layer"), make([]byte, size), 0o600))
	return path
}

func metricValue(t *testing.T, r *metrics.Recorder, name string) float64 {
	t.Helper()
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != metrics.Prefix+name {
			continue
		}
		require.Len(t, family.Metric, 1)
		if counter := family.Metric[0].Counter; counter != nil {
			return counter.GetValue()
		}
		return family.Metric[0].GetGauge().GetValue()
	}
	t.Fatalf("metric %s was not collected", name)
	return 0
}

func TestReaperRemovesOnlyDirectoriesOfDeadProcesses(t *testing.T) {
	root := t.TempDir()
	live := tempDir(t, root, "trivy-"+strconv.Itoa(os.Getpid()), 16)
	dead := tempDir(t, root, "trivy-"+strconv.Itoa(deadPID), 4096)
	report := tempDir(t, root, "scan_report_123", 16)
	unnumbered := tempDir(t, root, "trivy-cache", 16)

	recorder := metrics.New(true)
	r := &Reaper{metrics: recorder, root: root, self: os.Getpid()}
	r.sweep()

	require.NoDirExists(t, dead)
	for _, path := range []string{live, report, unnumbered} {
		require.DirExists(t, path)
	}
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_reaped_total"))
	// Only the live scan's directory is left; the other two are not Trivy's.
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_present"))

	// A second sweep has nothing left to do.
	r.sweep()
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_reaped_total"))
}

func TestReaperRunsWithoutMetricsAndStopsCleanly(t *testing.T) {
	root := t.TempDir()
	dead := tempDir(t, root, "trivy-"+strconv.Itoa(deadPID), 16)
	r := &Reaper{metrics: metrics.New(false), root: root, self: os.Getpid()}
	stop := r.Start(context.Background())
	require.Eventually(t, func() bool {
		_, err := os.Stat(dead)
		return os.IsNotExist(err)
	}, 5*time.Second, 10*time.Millisecond)
	stop()
}

func TestReaperSurvivesAMissingTempRoot(t *testing.T) {
	r := &Reaper{metrics: metrics.New(true), root: filepath.Join(t.TempDir(), "gone"), self: os.Getpid()}
	r.sweep()
	require.Zero(t, metricValue(t, r.metrics, "temp_dirs_reaped_total"))
}

func TestDirectorySizeCountsRegularFilesOnly(t *testing.T) {
	root := t.TempDir()
	path := tempDir(t, root, "trivy-1", 4096)
	require.NoError(t, os.Symlink(filepath.Join(path, "fanal", "layer"), filepath.Join(path, "link")))
	require.EqualValues(t, 4096, directorySize(path))
}
