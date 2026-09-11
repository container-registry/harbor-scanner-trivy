package queue

import "context"

type Worker interface {
	Start(ctx context.Context)
	Stop()
}
