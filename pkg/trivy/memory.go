package trivy

import (
	"os"
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

// childGoMemLimit resolves the GOMEMLIMIT for the Trivy child. An empty setting
// derives one from the cgroup, "off" passes the environment through unchanged,
// and anything else is handed to the runtime verbatim so operators can use the
// suffixed forms ("2GiB") the adapter does not need to understand.
func childGoMemLimit(configured string, paths ...string) string {
	switch configured {
	case "off":
		return ""
	case "":
		limit, ok := cgroupMemoryLimit(paths...)
		if !ok {
			return ""
		}
		return strconv.FormatInt(int64(float64(limit)*goMemLimitShare), 10)
	default:
		return configured
	}
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
		limit, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
		// "max" in v2 and a saturated counter in v1 both mean unlimited, which
		// is the state the runtime is already in.
		if err != nil || limit <= 0 || limit >= 1<<62 {
			continue
		}
		return limit, true
	}
	return 0, false
}
