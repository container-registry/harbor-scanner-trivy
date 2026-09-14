package api

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/stretchr/testify/require"
)

func TestListenAndServeReturnsNormallyAfterShutdown(t *testing.T) {
	s, err := NewServer(etc.API{Addr: "127.0.0.1:0"}, http.NotFoundHandler())
	require.NoError(t, err)
	// Shutdown before ListenAndServe must also be safe when SIGTERM races startup.
	require.NoError(t, s.server.Shutdown(context.Background()))
	require.NoError(t, s.ListenAndServe())
}

func TestListenAndServeReturnsListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	s, err := NewServer(etc.API{Addr: listener.Addr().String()}, http.NotFoundHandler())
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("listener failure was not returned")
	}
}
