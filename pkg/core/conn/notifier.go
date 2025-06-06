package conn

import (
	"context"
	"net"
)

// CloseNotifier is a type that wraps a network connection and provides a mechanism to signal when the connection is closed.
type CloseNotifier struct {
	net.Conn
	done chan struct{}
}

// NewCloseNotifier creates and returns a CloseNotifier wrapping the given network connection.
// It initializes a channel to signal when the connection is closed.
func NewCloseNotifier(conn net.Conn) *CloseNotifier {
	return &CloseNotifier{
		Conn: conn,
		done: make(chan struct{}),
	}
}

// WaitClose blocks until the CloseNotifier is closed or the provided context is canceled.
// It listens for the closure signal or context cancellation, whichever occurs first.
func (c *CloseNotifier) WaitClose(ctx context.Context) {
	select {
	case <-c.done:
	case <-ctx.Done():
	}
}

// Close terminates the underlying connection and signals closure via the done channel.
// It ensures the done channel is closed after invoking the connection's Close method.
// Returns an error if closing the connection fails.
func (c *CloseNotifier) Close() error {
	defer close(c.done)

	return c.Conn.Close()
}
