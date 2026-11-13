package testdatasource

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"slices"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/datasource"
	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// twoBlockZstdFrame is a zstd frame whose Huffman-weight FSE tables use
// tableLog 15. The second block's only normalized count is 1<<15. v1.20.0
// stores that count in an int16, so the decoder keeps the first block's
// fse table and panics. v1.20.2 rejects the count and returns an error.
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

func twoFrameZstdStream(oneFrame []byte) []byte {
	return slices.Concat(oneFrame[:6], []byte{0x75, 0x06, 0x00}, oneFrame[9:215], oneFrame[:6], oneFrame[215:])
}

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

func recordBatchBody(t *testing.T, file []byte) []byte {
	t.Helper()
	require.Greater(t, len(file), 16)
	require.Equal(t, []byte("ARROW1"), file[:6])
	require.Equal(t, []byte("ARROW1"), file[len(file)-6:])

	footerSize := int(binary.LittleEndian.Uint32(file[len(file)-10 : len(file)-6]))
	footerStart := len(file) - 10 - footerSize
	require.Greater(t, footerStart, 8)

	off := 8
	metaEnd := ipcMessageEnd(t, file, off)
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

func TestCraftedZstdArrowScenarioDoesNotCrash(t *testing.T) {
	s := &Service{
		scenarios: map[kinds.TestDataQueryType]*Scenario{},
		queryMux:  datasource.NewQueryTypeMux(),
		logger:    backend.NewLoggerWith("logger", "testdata-zstd"),
	}
	s.registerScenarios()

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
			raw, err := json.Marshal(map[string]string{
				"stringInput": base64.StdEncoding.EncodeToString(arrowFile),
			})
			require.NoError(t, err)
			req := &backend.QueryDataRequest{Queries: []backend.DataQuery{{
				RefID:     "A",
				QueryType: string(kinds.TestDataQueryTypeArrow),
				JSON:      raw,
			}}}

			t.Run("query-data", func(t *testing.T) {
				_, err := s.QueryData(context.Background(), req)
				require.Error(t, err)
			})
			t.Run("handler", func(t *testing.T) {
				_, err := s.handleArrowScenario(context.Background(), req)
				require.Error(t, err)
			})
		})
	}
}
