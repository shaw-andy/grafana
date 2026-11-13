package grpcplugin

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana-plugin-sdk-go/genproto/pluginv2"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/chunked"
)

// twoBlockZstdFrame is a zstd frame whose Huffman-weight FSE tables use
// tableLog 15. The second block's only normalized count is 1<<15. v1.20.0
// stores that count in an int16, so the decoder keeps the first block's
// fse table and panics. v1.20.2 rejects the count and returns an error.
// Byte layout matches klauspost/compress v1.20.2 zstd.TestDecoderHuffWeightsTableLog.
func twoBlockZstdFrame() []byte {
	return slices.Concat(
		[]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00, 0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f},
		bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37),
		[]byte{0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0, 0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51, 0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a},
		bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365),
		[]byte{0x8c, 0x31},
		bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365),
		[]byte{0x63, 0x2c},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
		[]byte{0x31, 0x46},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
		[]byte{0x31, 0x06, 0x00},
	)
}

// twoFrameZstdStream is the same two blocks in separate frames. The decoder
// returns the first block's huffman scratch to a pool and the second frame
// reuses it.
func twoFrameZstdStream(oneFrame []byte) []byte {
	return slices.Concat(oneFrame[:6], []byte{0x75, 0x06, 0x00}, oneFrame[9:215], oneFrame[:6], oneFrame[215:])
}

// arrowFileWithZstdPayload writes a real Arrow IPC file with ZSTD body
// compression, then replaces the record-batch compressed buffer with payload.
// The file header, schema, and buffer metadata stay intact, so the reader
// reaches klauspost's streaming decoder the same way UnmarshalArrowFrame does.
func arrowFileWithZstdPayload(t *testing.T, payload []byte) []byte {
	t.Helper()

	schema := arrow.NewSchema([]arrow.Field{{
		Name:     "v",
		Type:     arrow.PrimitiveTypes.Int64,
		Nullable: true,
	}}, nil)
	bld := array.NewInt64Builder(memory.DefaultAllocator)
	defer bld.Release()
	rng := rand.New(rand.NewSource(1))
	vals := make([]int64, 12000)
	for i := range vals {
		vals[i] = rng.Int63()
	}
	bld.AppendValues(vals, nil)
	col := bld.NewArray()
	defer col.Release()
	rec := array.NewRecord(schema, []arrow.Array{col}, int64(len(vals)))
	defer rec.Release()

	var buf bytes.Buffer
	w, err := ipc.NewFileWriter(&buf, ipc.WithSchema(schema), ipc.WithZstd())
	require.NoError(t, err)
	require.NoError(t, w.Write(rec))
	require.NoError(t, w.Close())

	out := bytes.Clone(buf.Bytes())
	body := recordBatchBody(t, out)
	require.GreaterOrEqual(t, len(body), 8+len(payload))
	require.Equal(t, []byte{0x28, 0xb5, 0x2f, 0xfd}, body[8:12])
	copy(body[8:], payload)
	return out
}

// recordBatchBody returns the record-batch body of an Arrow file that contains
// a schema message (no body) followed by one record batch.
func recordBatchBody(t *testing.T, file []byte) []byte {
	t.Helper()
	require.Greater(t, len(file), 16)
	require.Equal(t, []byte("ARROW1"), file[:6])
	require.Equal(t, []byte("ARROW1"), file[len(file)-6:])

	footerSize := int(binary.LittleEndian.Uint32(file[len(file)-10 : len(file)-6]))
	footerStart := len(file) - 10 - footerSize
	require.Greater(t, footerStart, 8)

	// Magic is padded to an 8-byte boundary.
	off := 8
	metaEnd := ipcMessageEnd(t, file, off)
	// Schema messages have an empty body, so the record batch follows immediately.
	require.Equal(t, byte(0xff), file[metaEnd])
	bodyStart := ipcMessageEnd(t, file, metaEnd)
	require.Less(t, bodyStart, footerStart)
	return file[bodyStart:footerStart]
}

func ipcMessageEnd(t *testing.T, file []byte, off int) int {
	t.Helper()
	require.LessOrEqual(t, off+8, len(file))
	cont := binary.LittleEndian.Uint32(file[off : off+4])
	require.Equal(t, uint32(0xffffffff), cont)
	metaLen := int(binary.LittleEndian.Uint32(file[off+4 : off+8]))
	require.Greater(t, metaLen, 0)
	end := off + 8 + metaLen
	require.LessOrEqual(t, end, len(file))
	return end
}

func TestZstdArrowFrameRoundTrip(t *testing.T) {
	schema := arrow.NewSchema([]arrow.Field{{
		Name: "v",
		Type: arrow.PrimitiveTypes.Int64,
	}}, nil)
	bld := array.NewInt64Builder(memory.DefaultAllocator)
	defer bld.Release()
	bld.Append(7)
	col := bld.NewArray()
	defer col.Release()
	rec := array.NewRecord(schema, []arrow.Array{col}, 1)
	defer rec.Release()

	var buf bytes.Buffer
	w, err := ipc.NewFileWriter(&buf, ipc.WithSchema(schema), ipc.WithZstd())
	require.NoError(t, err)
	require.NoError(t, w.Write(rec))
	require.NoError(t, w.Close())

	frame, err := data.UnmarshalArrowFrame(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, 1, frame.Rows())
}

func TestCraftedZstdArrowFrameDoesNotCrash(t *testing.T) {
	one := twoBlockZstdFrame()
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "two-block-frame", payload: one},
		{name: "two-frames", payload: twoFrameZstdStream(one)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arrowFile := arrowFileWithZstdPayload(t, tc.payload)
			// Each subtest is one entry point. v1.20.0 panics in the zstd
			// stream goroutine, which kills the process. v1.20.2 returns an error.
			t.Run("unmarshal", func(t *testing.T) {
				_, err := data.UnmarshalArrowFrame(arrowFile)
				require.Error(t, err)
			})
			t.Run("query-data", func(t *testing.T) {
				client := &ClientV2{DataClient: &arrowFrameDataClient{frame: arrowFile}}
				_, err := client.QueryData(context.Background(), &backend.QueryDataRequest{})
				require.Error(t, err)
			})
			t.Run("query-chunked", func(t *testing.T) {
				client := &ClientV2{DataClient: &arrowFrameDataClient{frame: arrowFile}}
				err := client.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{}, nopChunkWriter{})
				require.Error(t, err)
			})
			t.Run("raw-response", func(t *testing.T) {
				err := chunked.ProcessRawResponse(context.Background(), backend.DataFrameFormat_JSON, &pluginv2.QueryDataResponse{
					Responses: map[string]*pluginv2.DataResponse{
						"A": {Frames: [][]byte{arrowFile}},
					},
				}, nopRawReceiver{})
				require.Error(t, err)
			})
			t.Run("chunked-http", func(t *testing.T) {
				rec := httptest.NewRecorder()
				err := chunked.NewChunkedHTTPWriter(rec).OnChunk(&pluginv2.QueryChunkedDataResponse{
					RefId:  "A",
					Frame:  arrowFile,
					Format: pluginv2.DataFrameFormat_ARROW,
				})
				require.Error(t, err)
			})
		})
	}
}

type nopChunkWriter struct{}

func (nopChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }
func (nopChunkWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}

type nopRawReceiver struct{}

func (nopRawReceiver) OnChunk(*pluginv2.QueryChunkedDataResponse) error { return nil }

type arrowFrameDataClient struct {
	pluginv2.DataClient
	frame []byte
}

func (c *arrowFrameDataClient) QueryData(context.Context, *pluginv2.QueryDataRequest, ...grpc.CallOption) (*pluginv2.QueryDataResponse, error) {
	return &pluginv2.QueryDataResponse{
		Responses: map[string]*pluginv2.DataResponse{
			"A": {
				Frames: [][]byte{c.frame},
				Format: pluginv2.DataFrameFormat_ARROW,
			},
		},
	}, nil
}

func (c *arrowFrameDataClient) QueryChunkedData(context.Context, *pluginv2.QueryChunkedDataRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pluginv2.QueryChunkedDataResponse], error) {
	return &oneChunkStream{frame: c.frame}, nil
}

type oneChunkStream struct {
	frame []byte
	sent  bool
}

func (s *oneChunkStream) Recv() (*pluginv2.QueryChunkedDataResponse, error) {
	if s.sent {
		return nil, io.EOF
	}
	s.sent = true
	return &pluginv2.QueryChunkedDataResponse{RefId: "A", Frame: s.frame}, nil
}

func (s *oneChunkStream) Header() (metadata.MD, error) { return nil, nil }
func (s *oneChunkStream) Trailer() metadata.MD         { return nil }
func (s *oneChunkStream) CloseSend() error             { return nil }
func (s *oneChunkStream) Context() context.Context     { return context.Background() }
func (s *oneChunkStream) SendMsg(any) error            { return nil }
func (s *oneChunkStream) RecvMsg(any) error            { return io.EOF }
