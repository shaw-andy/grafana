package notifications

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSendEmailCommandHandlerReturnsWhenContextEndsWithFullQueue fills the
// mail queue and does not start the sender. The next send must return an
// error once the caller context ends, instead of waiting on the channel.
func TestSendEmailCommandHandlerReturnsWhenContextEndsWithFullQueue(t *testing.T) {
	ns, _ := createSut(t, newBus(t))
	cmd := &SendEmailCommand{
		Subject:     "subject",
		To:          []string{"flood@example.com"},
		SingleEmail: true,
		Template:    "welcome_on_signup",
	}

	for range cap(ns.mailQueue) {
		require.NoError(t, ns.SendEmailCommandHandler(context.Background(), cmd))
	}
	t.Cleanup(func() {
		select {
		case <-ns.mailQueue:
		case <-time.After(2 * time.Second):
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ns.SendEmailCommandHandler(ctx, cmd)
	}()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("SendEmailCommandHandler blocked after the mail queue filled and the caller context ended")
	}
}
