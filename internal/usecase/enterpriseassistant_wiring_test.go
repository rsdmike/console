package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/device-management-toolkit/console/pkg/ea/ad"
)

func TestDialDirectoryReturnsNilInterfaceOnError(t *testing.T) {
	t.Parallel()

	// Nothing listens on port 1, so this fails whether ad.Dial is the skeleton
	// or the real client, without leaving the host.
	dir, err := dialDirectory(context.Background(), ad.Config{Domain: "example.invalid", Server: "127.0.0.1:1", Timeout: time.Second})
	require.Error(t, err)
	require.True(t, dir == nil, "a typed nil would make dir != nil and Close would panic")
}
