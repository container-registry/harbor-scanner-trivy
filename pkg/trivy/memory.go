package trivy

import (
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Go's heap is unlimited by default, so a scan that outgrows the container's
// memory limit is OOM-killed instead of being slowed down by garbage
// collection. GOMEMLIMIT is a soft limit, hence the headroom below it for the
// runtime's own allocations and for what Trivy maps outside the heap.
const goMemLimitShare = 0.8

// cgroup v2 first: a v1 path can also exist on a v2 host through the hybrid
// hierarchy, where it does not describe the effective limit.
var cgroupMemoryLimitPaths = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

const (
	cgroupMount    = "/sys/fs/cgroup"
	procSelfCgroup = "/proc/self/cgroup"
)

// goMemLimitSyntax is the shape the Go runtime accepts: a decimal integer with
// an optional exact unit suffix.
var goMemLimitSyntax = regexp.MustCompile(`^([0-9]+)(B|KiB|MiB|GiB|TiB)?$`)

var goMemLimitUnits = map[string]int64{
	"": 1, "B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
}

// validGoMemLimit reports whether the Go runtime will start on this value. The
// runtime is unforgiving about it, and in both directions: measured against a Go
// binary, "10GB", "1.5GiB" and " 2GiB" fail the syntax, while
// "9223372036854775808", "8EiB" and "99999999999TiB" pass the syntax and
// overflow the int64 the limit is held in. Every one of them makes the child
// print the value and exit 2 before main runs, which would fail every scan.
func validGoMemLimit(value string) bool {
	match := goMemLimitSyntax.FindStringSubmatch(value)
	if match == nil {
		return false
	}
	digits, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		// More digits than a uint64 holds, so far beyond the maximum.
		return false
	}
	unit := goMemLimitUnits[match[2]]
	return digits <= uint64(math.MaxInt64)/uint64(unit)
}

// childGoMemLimit resolves the GOMEMLIMIT for the Trivy child. An empty setting
// derives one from the cgroup, "off" passes the environment through unchanged,
// and a valid explicit setting is handed to the runtime as given.
func childGoMemLimit(configured string, paths ...string) string {
	switch {
	case configured == "off":
		return ""
	case configured == "":
		return cgroupGoMemLimit(paths...)
	case validGoMemLimit(configured):
		return configured
	default:
		// Falling back to the derived limit keeps the protection a typo would
		// otherwise remove, and keeps Trivy startable either way.
		slog.Warn("SCANNER_TRIVY_CHILD_GOMEMLIMIT is not a value the Go runtime accepts, deriving the limit instead",
			slog.String("configured", configured),
			slog.String("want", `an integer of at most 2^63-1 bytes, with no suffix or an exact B, KiB, MiB, GiB or TiB suffix, or "off"`))
		return cgroupGoMemLimit(paths...)
	}
}

func cgroupGoMemLimit(paths ...string) string {
	limit, ok := cgroupMemoryLimit(paths...)
	if !ok {
		return ""
	}
	return strconv.FormatInt(int64(float64(limit)*goMemLimitShare), 10)
}

func cgroupMemoryLimit(paths ...string) (int64, bool) {
	explicit := len(paths) > 0
	if !explicit {
		paths = cgroupMemoryLimitPaths
	}
	if limit, ok := readCgroupMemoryLimit(paths); ok {
		return limit, true
	}
	if explicit {
		return 0, false
	}
	// The fixed paths are this process's cgroup only when it has a cgroup
	// namespace of its own. Sharing the host's makes them the hierarchy root,
	// whose memory.max is usually "max", which would read as "no limit" and
	// silently drop the protection. Ask the kernel where this process actually
	// sits before concluding that.
	return readCgroupMemoryLimit(processCgroupMemoryPaths(procSelfCgroup, cgroupMount))
}

func readCgroupMemoryLimit(paths []string) (int64, bool) {
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// The file that answered is the authority. A v1 path can still exist on
		// a v2 host through the hybrid hierarchy, holding a finite number for a
		// hierarchy nothing enforces, so an unlimited v2 answer ends the search
		// rather than falling through to it.
		value := strings.TrimSpace(string(content))
		limit, err := strconv.ParseInt(value, 10, 64)
		// "max" in v2 and a saturated counter in v1 both mean unlimited, which
		// is the state the runtime is already in.
		if err != nil || limit <= 0 || limit >= 1<<62 {
			return 0, false
		}
		return limit, true
	}
	return 0, false
}

// processCgroupMemoryPaths turns /proc/self/cgroup into the limit files for this
// process's own cgroup, v2 line first.
func processCgroupMemoryPaths(proc, mount string) []string {
	content, err := os.ReadFile(proc)
	if err != nil {
		return nil
	}
	var paths []string
	for _, line := range strings.Split(string(content), "\n") {
		// hierarchy-ID:controller-list:cgroup-path
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) != 3 || fields[2] == "" || fields[2] == "/" {
			continue
		}
		rel := strings.TrimPrefix(fields[2], "/")
		switch {
		case fields[0] == "0" && fields[1] == "":
			paths = append(paths, filepath.Join(mount, rel, "memory.max"))
		case strings.Contains(fields[1], "memory"):
			paths = append(paths, filepath.Join(mount, "memory", rel, "memory.limit_in_bytes"))
		}
	}
	return paths
}
