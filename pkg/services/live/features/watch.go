package features

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/logging"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data/utils/jsoniter"
	"github.com/grafana/grafana-plugin-sdk-go/live"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/live/livecontext"
	"github.com/grafana/grafana/pkg/services/live/model"
)

// WatchRunner will start a watch task and broadcast results
type WatchRunner struct {
	publisher      model.ChannelPublisher
	configProvider apiserver.RestConfigProvider

	watchingMu sync.Mutex
	watching   map[string]*watcher // keyed by watchKey
}

func watchKey(ns string, channel string) string {
	return ns + "/" + channel
}

func NewWatchRunner(publisher model.ChannelPublisher, configProvider apiserver.RestConfigProvider) *WatchRunner {
	return &WatchRunner{
		publisher:      publisher,
		configProvider: configProvider,
		watching:       make(map[string]*watcher),
	}
}

func (b *WatchRunner) GetHandlerForPath(_ string) (model.ChannelHandler, error) {
	return b, nil // all dashboards share the same handler
}

// Valid paths look like: {version}/{resource}[={name}]/{user.uid}
// * v0alpha1/dashboards/u12345
// * v0alpha1/dashboards=ABCD/u12345
func (b *WatchRunner) OnSubscribe(ctx context.Context, u identity.Requester, e model.SubscribeEvent) (model.SubscribeReply, backend.SubscribeStreamStatus, error) {
	// To make sure we do not share resources across users, include the UID in the path
	userID := u.GetIdentifier()
	if u.GetIdentityType() == types.TypeAnonymous {
		userID = "anonymous"
	} else if userID == "" {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusPermissionDenied, fmt.Errorf("missing user identity")
	}
	if !strings.HasSuffix(e.Path, userID) {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusPermissionDenied, fmt.Errorf("path must end with user uid (%s)", userID)
	}

	// Each watch is owned by the live clients subscribed to it and must stop
	// once they are gone, so a subscription without a client cannot start one.
	clientID, ok := livecontext.GetContextClientID(ctx)
	if !ok || clientID == "" {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusPermissionDenied, fmt.Errorf("missing live client")
	}
	if err := ctx.Err(); err != nil {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusNotFound, err
	}

	key := watchKey(u.GetNamespace(), e.Channel)

	b.watchingMu.Lock()
	defer b.watchingMu.Unlock()

	if current, ok := b.watching[key]; ok {
		b.addSubscriberLocked(ctx, key, current, clientID)
		return model.SubscribeReply{
			JoinLeave: false,
			Presence:  false,
			Recover:   false,
		}, backend.SubscribeStreamStatusOK, nil
	}

	// Try to start a watcher for this request
	gvr, name, err := parseWatchRequest(e.Channel, userID)
	if err != nil {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusNotFound, err
	}

	// Test this with only provisiong support -- then we can evaluate a broader rollout
	if gvr.Group != provisioning.GROUP {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusPermissionDenied,
			fmt.Errorf("watching provisioned resources is OK allowed (for now)")
	}

	// doesn't matter what GetRestConfig sees for context, matters for watch below
	cfg, err := b.configProvider.GetRestConfig(context.Background())
	if err != nil {
		return model.SubscribeReply{}, backend.SubscribeStreamStatusNotFound, err
	}

	// The watch outlives this subscribe request, so it gets its own context that
	// is cancelled when the last subscriber leaves.
	watchCtx, cancel := context.WithCancel(context.Background())
	// add user to both requester and authInfo context keys, older implementations are still using requester
	watchCtx = identity.WithRequester(types.WithAuthInfo(watchCtx, u), u)
	uclient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		cancel()
		return model.SubscribeReply{}, backend.SubscribeStreamStatusNotFound, err
	}
	client := uclient.Resource(gvr).Namespace(u.GetNamespace())

	opts := v1.ListOptions{}
	if len(name) > 1 {
		opts.FieldSelector = "metadata.name=" + name
	}

	// Support resourceVersion from subscription data.
	if len(e.Data) > 0 {
		var subData struct {
			ResourceVersion string `json:"resourceVersion,omitempty"`
		}
		if err := json.Unmarshal(e.Data, &subData); err == nil && subData.ResourceVersion != "" {
			opts.ResourceVersion = subData.ResourceVersion
		}
	}

	watch, err := client.Watch(watchCtx, opts)
	if err != nil {
		cancel()
		return model.SubscribeReply{}, backend.SubscribeStreamStatusNotFound, err
	}

	current := &watcher{
		ns:          u.GetNamespace(),
		channel:     e.Channel,
		publisher:   b.publisher,
		watch:       watch,
		cancel:      cancel,
		subscribers: make(map[string]func() bool),
	}

	b.watching[key] = current
	b.addSubscriberLocked(ctx, key, current, clientID)
	go b.run(watchCtx, key, current)

	return model.SubscribeReply{
		JoinLeave: false, // need unsubscribe envents
		Presence:  false,
		Recover:   false,
	}, backend.SubscribeStreamStatusOK, nil
}

func parseWatchRequest(channel string, user string) (gvr schema.GroupVersionResource, name string, err error) {
	addr, err := live.ParseChannel(channel)
	if err != nil {
		return gvr, "", err
	}

	parts := strings.Split(addr.Path, "/")
	if len(parts) != 3 {
		return gvr, "", fmt.Errorf("expecting path: {version}/{resource}={name}/{user}")
	}
	if parts[2] != user {
		return gvr, "", fmt.Errorf("expecting user suffix: %s", user)
	}

	resource := strings.Split(parts[1], "=")
	gvr = schema.GroupVersionResource{
		Group:    addr.Namespace,
		Version:  parts[0],
		Resource: resource[0],
	}
	if len(resource) > 1 {
		name = resource[1]
	}
	return gvr, name, nil
}

// OnPublish is called when a client wants to broadcast on the websocket
func (b *WatchRunner) OnPublish(_ context.Context, u identity.Requester, e model.PublishEvent) (model.PublishReply, backend.PublishStreamStatus, error) {
	return model.PublishReply{}, backend.PublishStreamStatusNotFound, fmt.Errorf("watch does not support publish")
}

// OnUnsubscribe is called when a live client leaves a watch channel, including
// when its connection closes.
func (b *WatchRunner) OnUnsubscribe(ns string, channel string, clientID string) {
	key := watchKey(ns, channel)

	b.watchingMu.Lock()
	defer b.watchingMu.Unlock()

	if current, ok := b.watching[key]; ok {
		b.removeSubscriberLocked(key, current, clientID)
	}
}

// addSubscriberLocked ties the subscriber to its connection context, so the
// subscription is released even if no unsubscribe event is delivered for it.
func (b *WatchRunner) addSubscriberLocked(ctx context.Context, key string, w *watcher, clientID string) {
	if _, ok := w.subscribers[clientID]; ok {
		return
	}
	w.subscribers[clientID] = context.AfterFunc(ctx, func() {
		b.watchingMu.Lock()
		defer b.watchingMu.Unlock()
		if b.watching[key] == w {
			b.removeSubscriberLocked(key, w, clientID)
		}
	})
}

func (b *WatchRunner) removeSubscriberLocked(key string, w *watcher, clientID string) {
	stop, ok := w.subscribers[clientID]
	if !ok {
		return
	}
	stop()
	delete(w.subscribers, clientID)
	if len(w.subscribers) == 0 {
		b.stopLocked(key, w)
	}
}

func (b *WatchRunner) stopLocked(key string, w *watcher) {
	if b.watching[key] == w {
		delete(b.watching, key)
	}
	for _, stop := range w.subscribers {
		stop()
	}
	clear(w.subscribers)
	w.cancel()
	w.watch.Stop()
}

func (b *WatchRunner) run(ctx context.Context, key string, w *watcher) {
	// When the stream ends on its own the frontend resubscribes, which opens a
	// new watch.
	defer func() {
		b.watchingMu.Lock()
		defer b.watchingMu.Unlock()
		b.stopLocked(key, w)
	}()

	logger := logging.FromContext(ctx).With("channel", w.channel)

	ch := w.watch.ResultChan()
	for {
		select {
		// This is sent when there are no longer any subscriptions
		case <-ctx.Done():
			logger.Info("context done", "channel", w.channel)
			return

		// Each watch event
		case event, ok := <-ch:
			if !ok {
				logger.Info("watch stream broken", "channel", w.channel)
				return
			}

			data, err := marshalWatchEvent(event)
			if err != nil {
				logger.Error("marshal error", "channel", w.channel, "err", err)
				continue
			}

			err = w.publisher(w.ns, w.channel, data)
			if err != nil {
				logger.Error("publish error", "channel", w.channel, "err", err)
				return
			}
		}
	}
}

type watcher struct {
	ns        string
	channel   string
	publisher model.ChannelPublisher
	watch     watch.Interface
	cancel    context.CancelFunc

	// live client ID -> stops the release on connection close
	subscribers map[string]func() bool
}

// marshalWatchEvent serializes a watch event to JSON. This is extracted from the
// run loop so that defer correctly returns the borrowed jsoniter stream each call.
func marshalWatchEvent(event watch.Event) ([]byte, error) {
	cfg := jsoniter.ConfigCompatibleWithStandardLibrary
	stream := cfg.BorrowStream(nil)
	defer cfg.ReturnStream(stream)

	stream.WriteObjectStart()
	stream.WriteObjectField("type")
	stream.WriteString(string(event.Type))
	stream.WriteMore()
	stream.WriteObjectField("object")
	stream.WriteVal(event.Object)
	stream.WriteObjectEnd()

	if stream.Error != nil {
		return nil, stream.Error
	}

	buf := stream.Buffer()
	data := make([]byte, len(buf))
	copy(data, buf)
	return data, nil
}
