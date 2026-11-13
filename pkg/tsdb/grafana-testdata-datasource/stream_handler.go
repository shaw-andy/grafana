package testdatasource

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// Every accepted path becomes its own Live channel with a dedicated stream
// goroutine, so only these exact paths may be subscribed to.
var testStreams = map[string]testStreamConfig{
	"random-2s-stream": {
		Interval: 2 * time.Second,
	},
	"random-flakey-stream": {
		Interval: 100 * time.Millisecond,
		Drop:     0.90, // keep 10%
	},
	"random-labeled-stream": {
		Interval: 200 * time.Millisecond,
		Drop:     0.2, // keep 80%
		Labeled:  true,
	},
	"random-20Hz-stream": {
		Interval: 50 * time.Millisecond,
	},
}

func (s *Service) SubscribeStream(ctx context.Context, req *backend.SubscribeStreamRequest) (*backend.SubscribeStreamResponse, error) {
	ctxLogger := s.logger.FromContext(ctx)

	if strings.HasPrefix(req.Path, "sim/") {
		return s.sims.SubscribeStream(ctx, req)
	}

	conf, ok := testStreams[req.Path]
	if !ok {
		ctxLogger.Debug("Refusing access to unknown stream", "path", req.Path, "user", req.PluginContext.User)
		return &backend.SubscribeStreamResponse{
			Status: backend.SubscribeStreamStatusNotFound,
		}, nil
	}
	ctxLogger.Debug("Allowing access to stream", "path", req.Path, "user", req.PluginContext.User)

	frame := s.frame
	if conf.Labeled {
		frame = s.labelFrame
	}
	initialData, err := backend.NewInitialFrame(frame, data.IncludeSchemaOnly)
	if err != nil {
		return nil, err
	}

	return &backend.SubscribeStreamResponse{
		Status:      backend.SubscribeStreamStatusOK,
		InitialData: initialData,
	}, nil
}

func (s *Service) PublishStream(ctx context.Context, req *backend.PublishStreamRequest) (*backend.PublishStreamResponse, error) {
	ctxLogger := s.logger.FromContext(ctx)
	ctxLogger.Debug("Attempt to publish into stream", "path", req.Path, "user", req.PluginContext.User)

	if strings.HasPrefix(req.Path, "sim/") {
		return s.sims.PublishStream(ctx, req)
	}

	return &backend.PublishStreamResponse{
		Status: backend.PublishStreamStatusPermissionDenied,
	}, nil
}

func (s *Service) RunStream(ctx context.Context, request *backend.RunStreamRequest, sender *backend.StreamSender) error {
	ctxLogger := s.logger.FromContext(ctx)
	ctxLogger.Debug("New stream call", "path", request.Path)

	if strings.HasPrefix(request.Path, "sim/") {
		return s.sims.RunStream(ctx, request, sender)
	}

	conf, ok := testStreams[request.Path]
	if !ok {
		return fmt.Errorf("testdata plugin does not support path: %s", request.Path)
	}
	return s.runTestStream(ctx, request.Path, conf, sender)
}

type testStreamConfig struct {
	Interval time.Duration
	Drop     float64
	Labeled  bool
}

func (s *Service) runTestStream(ctx context.Context, path string, conf testStreamConfig, sender *backend.StreamSender) error {
	ctxLogger := s.logger.FromContext(ctx)
	spread := 50.0
	walker := rand.Float64() * 100

	ticker := time.NewTicker(conf.Interval)
	defer ticker.Stop()

	labelFrame := data.NewFrame("labeled",
		data.NewField("labels", nil, make([]string, 2)),
		data.NewField("Time", nil, make([]time.Time, 2)),
		data.NewField("Value", nil, make([]float64, 2)),
	)

	for {
		select {
		case <-ctx.Done():
			ctxLogger.Debug("Stop streaming data for path", "path", path)
			return ctx.Err()
		case t := <-ticker.C:
			if rand.Float64() < conf.Drop {
				continue
			}

			mode := data.IncludeDataOnly
			delta := rand.Float64() - 0.5
			walker += delta

			if conf.Labeled {
				secA := t.Second() / 3
				secB := t.Second() / 7

				labelFrame.Fields[0].Set(0, fmt.Sprintf("s=A,s=p%d,x=X", secA))
				labelFrame.Fields[1].Set(0, t)
				labelFrame.Fields[2].Set(0, walker)

				labelFrame.Fields[0].Set(1, fmt.Sprintf("s=B,s=p%d,x=X", secB))
				labelFrame.Fields[1].Set(1, t)
				labelFrame.Fields[2].Set(1, walker+10)
				if err := sender.SendFrame(labelFrame, mode); err != nil {
					return err
				}
			} else {
				s.frame.Fields[0].Set(0, t)
				s.frame.Fields[1].Set(0, walker)                                // Value
				s.frame.Fields[2].Set(0, walker-((rand.Float64()*spread)+0.01)) // Min
				s.frame.Fields[3].Set(0, walker+((rand.Float64()*spread)+0.01)) // Max
				if err := sender.SendFrame(s.frame, mode); err != nil {
					return err
				}
			}
		}
	}
}
