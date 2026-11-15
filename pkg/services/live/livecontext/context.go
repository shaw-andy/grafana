package livecontext

import (
	"context"
)

type streamIDContextKey struct{}

func SetContextStreamID(ctx context.Context, streamID string) context.Context {
	ctx = context.WithValue(ctx, streamIDContextKey{}, streamID)
	return ctx
}

func GetContextStreamID(ctx context.Context) (string, bool) {
	if val := ctx.Value(streamIDContextKey{}); val != nil {
		values, ok := val.(string)
		return values, ok
	}
	return "", false
}

type clientIDContextKey struct{}

func SetContextClientID(ctx context.Context, clientID string) context.Context {
	ctx = context.WithValue(ctx, clientIDContextKey{}, clientID)
	return ctx
}

func GetContextClientID(ctx context.Context) (string, bool) {
	if val := ctx.Value(clientIDContextKey{}); val != nil {
		values, ok := val.(string)
		return values, ok
	}
	return "", false
}

type channelIDContextKey struct{}

func SetContextChannelID(ctx context.Context, channelID string) context.Context {
	ctx = context.WithValue(ctx, channelIDContextKey{}, channelID)
	return ctx
}

func GetContextChannelID(ctx context.Context) (string, bool) {
	if val := ctx.Value(channelIDContextKey{}); val != nil {
		values, ok := val.(string)
		return values, ok
	}
	return "", false
}
