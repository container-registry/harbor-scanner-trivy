package queue

import (
	"context"
	"time"
)

type Worker interface {
	Start(ctx context.Context)
	Stop()
	// Healthy reports whether the job backend can deliver work: the client
	// answers and the consumer group the worker reads from exists.
	Healthy(ctx context.Context) error
	// Active reports whether the read loop is still running. It is separate
	// from Healthy because a wedged loop and an unreachable backend need
	// different operator responses.
	Active() error
}

// healthTimeout bounds the readiness probe's own Redis call, well inside the
// probe timeout so a slow backend fails the check rather than the probe.
const healthTimeout = 5 * time.Second
