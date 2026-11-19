package testdatasource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana-plugin-sdk-go/genproto/pluginv2"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/chunked"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/grpcplugin"
)

// craftedZstdFrameSHA256 is the frame below. It is two zstd blocks whose Huffman
// weights use an FSE table the decoder in klauspost/compress v1.20.0 panics on.
const craftedZstdFrameSHA256 = "5f0ea717c1eae43ca55d0aa3f5b671e0577135cd514d0f9058dd6cfd7c551b5d"

func craftedZstdFrame(t *testing.T) []byte {
	t.Helper()
	frame := append([]byte{},
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00, 0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f)
	frame = append(frame, bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37)...)
	frame = append(frame,
		0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0, 0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51, 0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a)
	frame = append(frame, bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365)...)
	frame = append(frame, 0x8c, 0x31)
	frame = append(frame, bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365)...)
	frame = append(frame, 0x63, 0x2c)
	frame = append(frame, bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365)...)
	frame = append(frame, 0x31, 0x46)
	frame = append(frame, bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365)...)
	frame = append(frame, 0x31, 0x06, 0x00)
	sum := sha256.Sum256(frame)
	require.Equal(t, craftedZstdFrameSHA256, hex.EncodeToString(sum[:]), "crafted frame bytes drifted")
	return frame
}

// zstdArrowFile is an Arrow IPC file whose record-batch body is marked ZSTD and
// whose compressed values buffer is the crafted frame. Arrow's reader feeds
// that buffer to klauspost/compress/zstd.
func zstdArrowFile(t *testing.T, payload []byte) []byte {
	t.Helper()
	mem := memory.NewGoAllocator()
	schema := arrow.NewSchema([]arrow.Field{{
		Name: "v", Type: arrow.PrimitiveTypes.Uint8, Nullable: false,
	}}, nil)
	builder := array.NewUint8Builder(mem)
	rng := rand.New(rand.NewSource(1))
	raw := make([]byte, 80_000)
	_, err := rng.Read(raw)
	require.NoError(t, err)
	builder.AppendValues(raw, nil)
	values := builder.NewArray()
	t.Cleanup(values.Release)
	rec := array.NewRecordBatch(schema, []arrow.Array{values}, int64(values.Len()))
	t.Cleanup(rec.Release)

	var buf bytes.Buffer
	w, err := ipc.NewFileWriter(&buf, ipc.WithSchema(schema), ipc.WithZstd(), ipc.WithAllocator(mem))
	require.NoError(t, err)
	require.NoError(t, w.Write(rec))
	require.NoError(t, w.Close())

	out := buf.Bytes()
	magic := []byte{0x28, 0xb5, 0x2f, 0xfd}
	replaced := false
	for i := 8; i+len(magic) <= len(out); i++ {
		if !bytes.Equal(out[i:i+len(magic)], magic) {
			continue
		}
		size := binary.LittleEndian.Uint64(out[i-8 : i])
		if size != uint64(len(raw)) {
			continue
		}
		require.GreaterOrEqual(t, len(out)-i, len(payload))
		copy(out[i:], payload)
		replaced = true
		break
	}
	require.True(t, replaced, "arrow file had no zstd values buffer to replace")
	return out
}

// requireDecodeError fails while the decoder still panics. A panic on the
// calling goroutine is recovered by the Arrow reader and returned as a runtime
// error; a panic on the decoder goroutine crashes the test process. A fixed
// decoder returns a corruption error and leaves the process running.
func requireDecodeError(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	msg := err.Error()
	require.NotContains(t, msg, "runtime error")
	require.NotContains(t, msg, "index out of range")
	require.NotContains(t, strings.ToLower(msg), "panic")
}

func arrowQueryJSON(t *testing.T, file []byte) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"scenarioId":  "arrow",
		"stringInput": base64.StdEncoding.EncodeToString(file),
		"refId":       "A",
	})
	require.NoError(t, err)
	return raw
}

func TestArrowScenarioRejectsCraftedZstdFrame(t *testing.T) {
	file := zstdArrowFile(t, craftedZstdFrame(t))
	svc := ProvideService()
	_, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{
			RefID:     "A",
			QueryType: "arrow",
			JSON:      arrowQueryJSON(t, file),
		}},
	})
	requireDecodeError(t, err)
}

func TestChunkedArrowScenarioRejectsCraftedZstdFrame(t *testing.T) {
	file := zstdArrowFile(t, craftedZstdFrame(t))
	svc := ProvideService()
	err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{{
			RefID:     "A",
			QueryType: "arrow",
			JSON:      arrowQueryJSON(t, file),
		}},
	}, nopChunkWriter{})
	requireDecodeError(t, err)
}

type nopChunkWriter struct{}

func (nopChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }
func (nopChunkWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}

type framePlugin struct {
	frame []byte
}

func (f framePlugin) QueryData(context.Context, *pluginv2.QueryDataRequest, ...grpc.CallOption) (*pluginv2.QueryDataResponse, error) {
	return &pluginv2.QueryDataResponse{
		Responses: map[string]*pluginv2.DataResponse{
			"A": {
				Frames: [][]byte{f.frame},
				Format: pluginv2.DataFrameFormat_ARROW,
			},
		},
	}, nil
}

func (f framePlugin) QueryChunkedData(context.Context, *pluginv2.QueryChunkedDataRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pluginv2.QueryChunkedDataResponse], error) {
	return &frameStream{frame: f.frame}, nil
}

type frameStream struct {
	grpc.ClientStream
	frame []byte
	sent  bool
}

func (s *frameStream) Recv() (*pluginv2.QueryChunkedDataResponse, error) {
	if s.sent {
		return nil, io.EOF
	}
	s.sent = true
	return &pluginv2.QueryChunkedDataResponse{
		RefId:   "A",
		FrameId: "0",
		Frame:   s.frame,
		Format:  pluginv2.DataFrameFormat_ARROW,
	}, nil
}

func TestPluginQueryDataRejectsCraftedZstdFrame(t *testing.T) {
	file := zstdArrowFile(t, craftedZstdFrame(t))
	client := &grpcplugin.ClientV2{}
	client.DataClient = framePlugin{frame: file}
	_, err := client.QueryData(context.Background(), &backend.QueryDataRequest{
		Queries: []backend.DataQuery{{RefID: "A"}},
	})
	requireDecodeError(t, err)
}

func TestPluginChunkedDataRejectsCraftedZstdFrame(t *testing.T) {
	file := zstdArrowFile(t, craftedZstdFrame(t))
	client := &grpcplugin.ClientV2{}
	client.DataClient = framePlugin{frame: file}
	err := client.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{{RefID: "A"}},
	}, nopChunkWriter{})
	requireDecodeError(t, err)
}

type recordChunk struct {
	chunk *pluginv2.QueryChunkedDataResponse
}

func (r *recordChunk) OnChunk(chunk *pluginv2.QueryChunkedDataResponse) error {
	r.chunk = chunk
	return nil
}

func TestRawChunkResponseRejectsCraftedZstdFrame(t *testing.T) {
	file := zstdArrowFile(t, craftedZstdFrame(t))
	recv := &recordChunk{}
	err := chunked.ProcessRawResponse(context.Background(), backend.DataFrameFormat_JSON, &pluginv2.QueryDataResponse{
		Responses: map[string]*pluginv2.DataResponse{
			"A": {Frames: [][]byte{file}, Format: pluginv2.DataFrameFormat_ARROW},
		},
	}, recv)
	requireDecodeError(t, err)
	require.Nil(t, recv.chunk)
}

func TestChunkedHTTPWriterRejectsCraftedZstdFrame(t *testing.T) {
	file := zstdArrowFile(t, craftedZstdFrame(t))
	rec := httptest.NewRecorder()
	w := chunked.NewChunkedHTTPWriter(rec)
	err := w.OnChunk(&pluginv2.QueryChunkedDataResponse{
		RefId:  "A",
		Frame:  file,
		Format: pluginv2.DataFrameFormat_ARROW,
	})
	requireDecodeError(t, err)
}
