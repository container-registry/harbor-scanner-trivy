//go:build !linux && !darwin

package metrics

import (
	"errors"
	"os"
)

func maxRSS(*os.ProcessState) (float64, bool) { return 0, false }
func filesystem(string) (float64, float64, float64, error) {
	return 0, 0, 0, errors.New("filesystem metrics unsupported on this platform")
}
