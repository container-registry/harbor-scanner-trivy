package redisx

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"

	"github.com/stretchr/testify/require"

	"github.com/container-registry/harbor-scanner-trivy/pkg/etc"
	"github.com/stretchr/testify/assert"
)

func TestGetPool(t *testing.T) {
	t.Run("Should not return error when configured to connect to secure redis", func(t *testing.T) {
		_, err := NewClient(etc.RedisPool{
			URL: "rediss://hostname:6379",
		})
		assert.NoError(t, err)
	})

	t.Run("Should return error when configured with unsupported url scheme", func(t *testing.T) {
		_, err := NewClient(etc.RedisPool{
			URL: "https://hostname:6379",
		})
		assert.EqualError(t, err, "invalid redis URL scheme: https")
	})
}

func TestParseSentinelURL(t *testing.T) {
	testCases := []struct {
		configURL           string
		expectedSentinelURL SentinelURL
		expectedError       string
	}{
		{
			configURL: "redis+sentinel://harbor:s3cret@somehost:26379,otherhost:26479/mymaster/3",
			expectedSentinelURL: SentinelURL{
				Username: "harbor",
				Password: "s3cret",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    3,
			},
		},
		{
			configURL: "redis+sentinel://:s3cret@somehost:26379,otherhost:26479/mymaster/5",
			expectedSentinelURL: SentinelURL{
				Username: "",
				Password: "s3cret",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    5,
			},
		},
		{
			configURL: "redis+sentinel://:s3cret@somehost:26379,otherhost:26479/mymaster",
			expectedSentinelURL: SentinelURL{
				Username: "",
				Password: "s3cret",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    0,
			},
		},
		{
			configURL: "rediss+sentinel://foo:mypwd@somehost:26379,otherhost:26479/mymaster",
			expectedSentinelURL: SentinelURL{
				Username: "foo",
				Password: "mypwd",
				Addrs: []string{
					"somehost:26379",
					"otherhost:26479",
				},
				MonitorName: "mymaster",
				Database:    0,
			},
		},
		{
			configURL:     "redis+sentinel://:s3cret@somehost:26379,otherhost:26479/mymaster/X",
			expectedError: "invalid redis sentinel URL: invalid database number: X",
		},
		{
			configURL:     "redis+sentinel://:s3cret@somehost:26379,otherhost:26479",
			expectedError: "invalid redis sentinel URL: no master name",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.configURL, func(t *testing.T) {
			configURL, err := url.Parse(tc.configURL)
			require.NoError(t, err)

			sentinelURL, err := ParseSentinelURL(configURL)

			switch tc.expectedError {
			case "":
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSentinelURL, sentinelURL)
			default:
				assert.EqualError(t, err, tc.expectedError)
			}
		})
	}
}

func TestRedisCommandHonorsCallerDeadline(t *testing.T) {
	backend := miniredis.RunT(t)
	client, err := NewClient(etc.RedisPool{URL: "redis://" + backend.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())
	release := make(chan struct{})
	defer close(release)
	backend.Server().SetPreHook(func(_ *server.Peer, cmd string, _ ...string) bool {
		if cmd == "PING" {
			<-release
		}
		return false
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Ping(ctx).Err() }()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Redis ignored the caller deadline")
	}
}
