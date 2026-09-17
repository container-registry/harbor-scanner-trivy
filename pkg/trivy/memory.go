package trivy

import (
	"log/slog"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Go's heap is unlimited by default, so a scan that outgrows the container's
// memory limit is OOM-killed instead of being slowed down by garbage
// collection. GOMEMLIMIT is a soft limit, hence the headroom below it for the
// runtime's own allocations and for what Trivy maps outside the heap.
const goMemLimitShare = 0.8

// cgroup v2 first: a v1 path can also exist on a v2 host through the hybrid
// hierarchy, where it does not describe the effective limit. These are this
// process's own cgroup when the container has a cgroup namespace of its own,
// which is what the chart's runtime gives it.
var cgroupMemoryLimitPaths = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

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

// The setting is static for the life of the process, so its rejection is one
// fact worth one line, not one per scan.
var warnInvalidGoMemLimit sync.Once

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
		warnInvalidGoMemLimit.Do(func() {
			slog.Warn("SCANNER_TRIVY_CHILD_GOMEMLIMIT is not a value the Go runtime accepts, deriving the limit instead",
				slog.String("configured", configured),
				slog.String("want", `an integer of at most 2^63-1 bytes, with no suffix or an exact B, KiB, MiB, GiB or TiB suffix, or "off"`))
		})
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
	if len(paths) == 0 {
		paths = cgroupMemoryLimitPaths
	}
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
