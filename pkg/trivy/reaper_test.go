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
// for children, each holding what Trivy extracts.
func adapterRoot(t *testing.T, temp, name string, children ...int) string {
	t.Helper()
	path := filepath.Join(temp, name)
	for i, size := range children {
		child := filepath.Join(path, "scan-"+strconv.Itoa(i))
		require.NoError(t, os.MkdirAll(filepath.Join(child, "fanal"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(child, "fanal", "layer"), make([]byte, size), 0o600))
	}
	require.NoError(t, os.MkdirAll(path, 0o755))
	return path
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
// as a pid finds no process for almost every value, so anything that acted on
// the name would delete the layers of a scan that is running right now. The
// adapter never touches directories it did not create.
func TestReaperNeverTouchesTrivyScratchDirectories(t *testing.T) {
	temp := t.TempDir()
	random := adapterRoot(t, temp, "trivy-4000000000", 4096)
	ownPID := adapterRoot(t, temp, "trivy-"+strconv.Itoa(os.Getpid()), 16)
	unnumbered := adapterRoot(t, temp, "trivy-cache", 16)

	recorder := metrics.New(true)
	newReaper(t, recorder, temp).reapSiblings()

	for _, path := range []string{random, ownPID, unnumbered} {
		require.DirExists(t, path, "a directory the adapter does not own must survive")
	}
	require.Zero(t, metricValue(t, recorder, "temp_dirs_reaped_total"))
}

// One adapter per temp filesystem, so at startup every sibling root is a
// previous process's, however recent it looks and whatever pid it had.
func TestStartupRemovesEverySiblingRootAndKeepsItsOwn(t *testing.T) {
	temp := t.TempDir()
	recorder := metrics.New(true)
	r := newReaper(t, recorder, temp)
	own := adapterRoot(t, r.own.Path(), "", 16)
	killed := adapterRoot(t, temp, AdapterTempPrefix+"killed", 4096, 4096)
	restarted := adapterRoot(t, temp, AdapterTempPrefix+"restarted", 16)
	report := adapterRoot(t, temp, "scan_report_123", 16)

	stop := r.Start(context.Background())
	defer stop()

	require.NoDirExists(t, killed)
	require.NoDirExists(t, restarted)
	require.DirExists(t, own)
	require.DirExists(t, report)
	require.Equal(t, float64(2), metricValue(t, recorder, "temp_dirs_reaped_total"))
	// The one scan in flight under this process's own root.
	require.Equal(t, float64(1), metricValue(t, recorder, "temp_dirs_present"))
}

// After startup nothing else is removed: a root that appears later is not this
// process's to reason about, and the gauge only counts.
func TestNothingIsRemovedAfterStartup(t *testing.T) {
	temp := t.TempDir()
	recorder := metrics.New(true)
	r := newReaper(t, recorder, temp)
	stop := r.Start(context.Background())
	defer stop()

	late := adapterRoot(t, temp, AdapterTempPrefix+"late", 16)
	require.Never(t, func() bool {
		_, err := os.Stat(late)
		return os.IsNotExist(err)
	}, 200*time.Millisecond, 20*time.Millisecond)
	require.Zero(t, metricValue(t, recorder, "temp_dirs_reaped_total"))
}

func TestReaperRunsWithoutMetricsAndStopsCleanly(t *testing.T) {
	temp := t.TempDir()
	gone := adapterRoot(t, temp, AdapterTempPrefix+"gone", 16)
	stop := newReaper(t, metrics.New(false), temp).Start(context.Background())
	require.NoDirExists(t, gone)
	stop()
}

func TestReaperSurvivesAMissingTempRoot(t *testing.T) {
	temp := t.TempDir()
	recorder := metrics.New(true)
	r := newReaper(t, recorder, temp)
	r.root = filepath.Join(temp, "gone")
	stop := r.Start(context.Background())
	defer stop()
	require.Zero(t, metricValue(t, recorder, "temp_dirs_reaped_total"))
	require.Zero(t, metricValue(t, recorder, "temp_dirs_present"))
}

func TestChildCountIgnoresFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "scan-0"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "scan-1"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stray"), nil, 0o600))
	require.Equal(t, 2, childCount(root))
	require.Zero(t, childCount(filepath.Join(root, "absent")))
}
