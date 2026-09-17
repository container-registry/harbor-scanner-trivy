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

// adapterRoot builds a root as the adapter lays one out: scratch directories
// for children, each holding what Trivy extracts. Old enough to be past the age
// guard, which is what a root left by a previous pod looks like.
func adapterRoot(t *testing.T, temp, name string, children ...int) string {
	t.Helper()
	path := filepath.Join(temp, name)
	for i, size := range children {
		child := filepath.Join(path, "scan-"+strconv.Itoa(i))
		require.NoError(t, os.MkdirAll(filepath.Join(child, "fanal"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(child, "fanal", "layer"), make([]byte, size), 0o600))
	}
	require.NoError(t, os.MkdirAll(path, 0o755))
	age(t, path, reapMinAge+time.Minute)
	return path
}

func age(t *testing.T, path string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(path, when, when))
}

// testRoot is an adapter temp root the test owns, standing in for the one
// NewTempRoot creates under os.TempDir().
func testRoot(t *testing.T) *TempRoot {
	t.Helper()
	return &TempRoot{path: filepath.Join(t.TempDir(), AdapterTempPrefix+"test")}
}

func newReaper(t *testing.T, recorder *metrics.Recorder, temp string) *Reaper {
	t.Helper()
	own := filepath.Join(temp, AdapterTempPrefix+"own")
	require.NoError(t, os.MkdirAll(own, 0o755))
	return &Reaper{metrics: recorder, root: temp, own: &TempRoot{path: own}}
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

// Trivy names its scratch directory $TMPDIR/trivy-<random> (pkg/x/os.initTempDir
// calls os.MkdirTemp), and os.MkdirTemp's suffix is a decimal uint32. Reading it
// as a pid finds no process for almost every value, so a sweep that acted on the
// name would delete the layers of a scan that is running right now.
func TestReaperNeverTouchesTrivyScratchDirectories(t *testing.T) {
	temp := t.TempDir()
	random := adapterRoot(t, temp, "trivy-4000000000", 4096)
	ownPID := adapterRoot(t, temp, "trivy-"+strconv.Itoa(os.Getpid()), 16)
	unnumbered := adapterRoot(t, temp, "trivy-cache", 16)

	recorder := metrics.New(true)
	newReaper(t, recorder, temp).sweep(context.Background())

	for _, path := range []string{random, ownPID, unnumbered} {
		require.DirExists(t, path, "a directory the adapter does not own must survive")
	}
	require.Zero(t, metricValue(t, recorder, "temp_dirs_reaped_total"))
}

func TestReaperRemovesRootsOfAdapterProcessesThatAreGone(t *testing.T) {
	temp := t.TempDir()
	own := adapterRoot(t, temp, AdapterTempPrefix+"own", 16)
	gone := adapterRoot(t, temp, AdapterTempPrefix+"gone", 4096, 4096)
	report := adapterRoot(t, temp, "scan_report_123", 16)

	recorder := metrics.New(true)
	r := newReaper(t, recorder, temp)
	r.sweep(context.Background())

	require.NoDirExists(t, gone)
	require.DirExists(t, own)
	require.DirExists(t, report)
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_reaped_total"))
	// The one scan in flight under this process's own root.
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_present"))

	// A second sweep has nothing left to do.
	r.sweep(context.Background())
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_reaped_total"))
}

func TestReaperRunsWithoutMetricsAndStopsCleanly(t *testing.T) {
	temp := t.TempDir()
	gone := adapterRoot(t, temp, AdapterTempPrefix+"gone", 16)
	r := newReaper(t, metrics.New(false), temp)
	stop := r.Start(context.Background())
	require.Eventually(t, func() bool {
		_, err := os.Stat(gone)
		return os.IsNotExist(err)
	}, 5*time.Second, 10*time.Millisecond)
	stop()
}

func TestReaperLeavesRecentRootsAlone(t *testing.T) {
	temp := t.TempDir()
	// An adapter that started moments ago, which happens only where a second
	// adapter shares this temp filesystem.
	fresh := adapterRoot(t, temp, AdapterTempPrefix+"gone", 16)
	age(t, fresh, time.Minute)

	recorder := metrics.New(true)
	r := newReaper(t, recorder, temp)
	r.sweep(context.Background())
	require.DirExists(t, fresh)
	require.Zero(t, metricValue(t, recorder, "temp_dirs_reaped_total"))
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_present"))

	age(t, fresh, reapMinAge+time.Minute)
	r.sweep(context.Background())
	require.NoDirExists(t, fresh)
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_reaped_total"))
	require.Zero(t, metricValue(t, recorder, "temp_dirs_present"))
}

func TestFailedListingDropsTheDirectoryCount(t *testing.T) {
	temp := t.TempDir()
	adapterRoot(t, temp, AdapterTempPrefix+"own", 16)
	recorder := metrics.New(true)
	r := newReaper(t, recorder, temp)
	r.sweep(context.Background())
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_present"))

	// A count from the last sweep must not be left standing for this one.
	r.root = filepath.Join(temp, "gone")
	r.sweep(context.Background())
	requireNotCollected(t, recorder, "temp_dirs_present")
}

func TestReaperStopsOnACancelledContext(t *testing.T) {
	temp := t.TempDir()
	gone := adapterRoot(t, temp, AdapterTempPrefix+"gone", 16)
	recorder := metrics.New(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	newReaper(t, recorder, temp).sweep(ctx)
	require.DirExists(t, gone)
	requireNotCollected(t, recorder, "temp_dirs_present")
}

func requireNotCollected(t *testing.T, r *metrics.Recorder, name string) {
	t.Helper()
	families, err := r.Gatherer().Gather()
	require.NoError(t, err)
	for _, family := range families {
		require.NotEqual(t, metrics.Prefix+name, family.GetName())
	}
}

func TestReaperSurvivesAMissingTempRoot(t *testing.T) {
	r := newReaper(t, metrics.New(true), filepath.Join(t.TempDir(), "gone"))
	r.sweep(context.Background())
	require.Zero(t, metricValue(t, r.metrics, "temp_dirs_reaped_total"))
}

func TestDirectorySizeCountsRegularFilesOnly(t *testing.T) {
	temp := t.TempDir()
	path := adapterRoot(t, temp, AdapterTempPrefix+"1", 4096)
	require.NoError(t, os.Symlink(filepath.Join(path, "scan-0", "fanal", "layer"), filepath.Join(path, "link")))
	require.EqualValues(t, 4096, directorySize(path))
}
