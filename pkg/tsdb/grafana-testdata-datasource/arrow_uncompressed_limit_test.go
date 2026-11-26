package testdatasource

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

// attackerUncompressedLen is the uncompressed-length prefix written into an
// otherwise tiny compressed Arrow body. It is large enough that honoring it
// is unambiguous, and small enough that the test process can survive the
// allocation long enough to record it.
const attackerUncompressedLen = 32 << 20

// maxBytesDuringQuery is the most memory a rejected arrow query may allocate.
// It sits well below attackerUncompressedLen so a handler that still resizes
// to the length prefix fails, including one that checks the prefix and then
// decodes anyway.
const maxBytesDuringQuery = 4 << 20

func TestArrowScenarioRejectsUnboundedCompressedBuffer(t *testing.T) {
	svc := ProvideService()

	cases := []struct {
		name       string
		codec      ipc.Option
		queryType  string
		scenarioID string
	}{
		{name: "query type arrow lz4", codec: ipc.WithLZ4(), queryType: string(kindsArrow), scenarioID: string(kindsArrow)},
		{name: "query type arrow zstd", codec: ipc.WithZstd(), queryType: string(kindsArrow), scenarioID: string(kindsArrow)},
		{name: "scenario id arrow lz4", codec: ipc.WithLZ4(), queryType: "", scenarioID: string(kindsArrow)},
		{name: "scenario id arrow zstd", codec: ipc.WithZstd(), queryType: "", scenarioID: string(kindsArrow)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := arrowQueryWithInflatedUncompressedLength(t, tc.codec)
			require.Less(t, len(payload), maxBytesDuringQuery, "query payload itself must stay small")

			resp, err, panicked, alloc := queryArrow(svc, arrowQuery(t, tc.queryType, tc.scenarioID, payload))
			if panicked != nil || alloc > maxBytesDuringQuery || frameBytes(resp) > maxBytesDuringQuery {
				t.Fatalf("arrow scenario honored an attacker-controlled uncompressed length: panicked=%v err=%v alloc=%d frameBytes=%d payloadBytes=%d declared=%d",
					panicked, err, alloc, frameBytes(resp), len(payload), attackerUncompressedLen)
			}
		})
	}
}

func TestArrowChunkedScenarioRejectsUnboundedCompressedBuffer(t *testing.T) {
	svc := ProvideService()
	payload := arrowQueryWithInflatedUncompressedLength(t, ipc.WithZstd())
	require.Less(t, len(payload), maxBytesDuringQuery)

	writer := &captureChunkWriter{}
	respErr, panicked, alloc := queryArrowChunked(svc, arrowQuery(t, string(kindsArrow), string(kindsArrow), payload), writer)
	if panicked != nil || alloc > maxBytesDuringQuery || writer.bytes > maxBytesDuringQuery {
		t.Fatalf("chunked arrow scenario honored an attacker-controlled uncompressed length: panicked=%v err=%v alloc=%d frameBytes=%d payloadBytes=%d declared=%d",
			panicked, respErr, alloc, writer.bytes, len(payload), attackerUncompressedLen)
	}
}

// kindsArrow is the scenario id registered for the arrow handler. It is
// duplicated as a string here so the test does not depend on a particular
// generated alias if the handler is removed.
const kindsArrow = "arrow"

func arrowQuery(t *testing.T, queryType, scenarioID string, payload []byte) backend.DataQuery {
	t.Helper()
	model := map[string]any{
		"scenarioId":  scenarioID,
		"stringInput": base64.StdEncoding.EncodeToString(payload),
	}
	raw, err := json.Marshal(model)
	require.NoError(t, err)
	return backend.DataQuery{
		RefID:     "A",
		QueryType: queryType,
		JSON:      raw,
	}
}

func queryArrow(svc *Service, q backend.DataQuery) (resp *backend.QueryDataResponse, err error, panicked any, alloc uint64) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	defer func() {
		panicked = recover()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		alloc = after.TotalAlloc - before.TotalAlloc
	}()
	resp, err = svc.QueryData(context.Background(), &backend.QueryDataRequest{
		Queries: []backend.DataQuery{q},
	})
	return resp, err, nil, 0
}

type captureChunkWriter struct {
	bytes int
}

func (w *captureChunkWriter) WriteFrame(_ context.Context, _ string, _ string, f *data.Frame) error {
	w.bytes += frameSize(f)
	return nil
}

func (w *captureChunkWriter) WriteError(_ context.Context, _ string, _ backend.Status, _ error) error {
	return nil
}

func queryArrowChunked(svc *Service, q backend.DataQuery, w backend.ChunkedDataWriter) (err error, panicked any, alloc uint64) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	defer func() {
		panicked = recover()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		alloc = after.TotalAlloc - before.TotalAlloc
	}()
	err = svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{q},
	}, w)
	return err, nil, 0
}

func frameBytes(resp *backend.QueryDataResponse) int {
	if resp == nil {
		return 0
	}
	total := 0
	for _, r := range resp.Responses {
		for _, f := range r.Frames {
			total += frameSize(f)
		}
	}
	return total
}

func frameSize(f *data.Frame) int {
	if f == nil {
		return 0
	}
	total := 0
	for _, field := range f.Fields {
		if field == nil || field.Len() == 0 {
			continue
		}
		// Size accounts for the concrete values copied out of the Arrow buffer.
		total += field.Len() * fieldSizeOf(field)
	}
	return total
}

func fieldSizeOf(field *data.Field) int {
	if field.Type() == data.FieldTypeString || field.Type() == data.FieldTypeNullableString {
		return 16
	}
	return 8
}

// arrowQueryWithInflatedUncompressedLength builds a one-batch Arrow file whose
// body is actually compressed, then replaces the real uncompressed-length
// prefix with attackerUncompressedLen. The compressed bytes stay small.
func arrowQueryWithInflatedUncompressedLength(t *testing.T, codec ipc.Option) []byte {
	t.Helper()
	file, originalLen := compressedArrowFile(t, codec)
	require.Less(t, originalLen, int64(maxBytesDuringQuery))

	prefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(prefix, uint64(originalLen))
	idx := bytes.Index(file, prefix)
	require.NotEqual(t, -1, idx, "compressed buffer is missing its uncompressed-length prefix")
	require.Equal(t, -1, bytes.Index(file[idx+8:], prefix), "uncompressed-length prefix is not unique")

	patched := bytes.Clone(file)
	binary.LittleEndian.PutUint64(patched[idx:], uint64(attackerUncompressedLen))
	return patched
}

func compressedArrowFile(t *testing.T, codec ipc.Option) ([]byte, int64) {
	t.Helper()
	mem := memory.NewGoAllocator()
	schema := arrow.NewSchema([]arrow.Field{{
		Name:     "v",
		Type:     arrow.PrimitiveTypes.Int64,
		Nullable: false,
	}}, nil)
	builder := array.NewRecordBuilder(mem, schema)
	defer builder.Release()

	const rows = 4096
	values := builder.Field(0).(*array.Int64Builder)
	for i := 0; i < rows; i++ {
		values.Append(0)
	}
	rec := builder.NewRecordBatch()
	defer rec.Release()

	var buf bytes.Buffer
	w, err := ipc.NewFileWriter(&buf, ipc.WithSchema(schema), codec)
	require.NoError(t, err)
	require.NoError(t, w.Write(rec))
	require.NoError(t, w.Close())

	// Non-nullable primitive batches have a values buffer of rows*8 bytes.
	// That length is stored as the little-endian prefix of a compressed body
	// buffer when the writer keeps the compressed bytes.
	return buf.Bytes(), int64(rows) * 8
}
