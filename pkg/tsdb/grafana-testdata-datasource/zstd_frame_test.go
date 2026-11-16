package testdatasource

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/kinds"
)

// craftedZstdFrame is the two-block frame from klauspost/compress v1.20.2
// zstd.TestDecoderHuffWeightsTableLog. v1.20.0 panics while decoding it;
// v1.20.2 returns an error. Both shapes (one frame, and the same blocks split
// across two frames) are included because the decoder keeps Huffman state
// between them.
func craftedZstdFrames() [][]byte {
	oneFrame := append([]byte{},
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00,
		0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f)
	oneFrame = append(oneFrame, bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37)...)
	oneFrame = append(oneFrame,
		0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0,
		0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51,
		0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a)
	oneFrame = append(oneFrame, bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365)...)
	oneFrame = append(oneFrame, 0x8c, 0x31)
	oneFrame = append(oneFrame, bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365)...)
	oneFrame = append(oneFrame, 0x63, 0x2c)
	oneFrame = append(oneFrame, bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365)...)
	oneFrame = append(oneFrame, 0x31, 0x46)
	oneFrame = append(oneFrame, bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365)...)
	oneFrame = append(oneFrame, 0x31, 0x06, 0x00)

	twoFrames := append([]byte{}, oneFrame[:6]...)
	twoFrames = append(twoFrames, 0x75, 0x06, 0x00)
	twoFrames = append(twoFrames, oneFrame[9:215]...)
	twoFrames = append(twoFrames, oneFrame[:6]...)
	twoFrames = append(twoFrames, oneFrame[215:]...)
	return [][]byte{oneFrame, twoFrames}
}

// arrowFileWithZstdPayload builds an Arrow IPC file whose single values buffer
// is marked zstd-compressed and whose compressed bytes start with payload.
// The writer emits a normal compressed buffer large enough to hold payload;
// the compressed bytes are then overwritten so the reader passes payload to
// the zstd streaming decoder without any other change to the file metadata.
func arrowFileWithZstdPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	mem := memory.NewGoAllocator()
	schema := arrow.NewSchema([]arrow.Field{{
		Name: "v", Type: arrow.PrimitiveTypes.Uint8, Nullable: false,
	}}, nil)
	raw := make([]byte, len(payload)+64*1024)
	rnd := rand.New(rand.NewSource(1))
	_, _ = rnd.Read(raw)

	b := array.NewUint8Builder(mem)
	b.AppendValues(raw, nil)
	col := b.NewArray()
	defer col.Release()
	rec := array.NewRecord(schema, []arrow.Array{col}, int64(len(raw)))
	defer rec.Release()

	var buf bytes.Buffer
	w, err := ipc.NewFileWriter(&buf, ipc.WithSchema(schema), ipc.WithZstd())
	require.NoError(t, err)
	require.NoError(t, w.Write(rec))
	require.NoError(t, w.Close())

	file := buf.Bytes()
	prefix := make([]byte, 8)
	binary.LittleEndian.PutUint64(prefix, uint64(len(raw)))
	// The body buffer is the length prefix followed by a real zstd frame.
	// The same length is also stored in the record metadata, so match the magic.
	marker := append(append([]byte{}, prefix...), 0x28, 0xb5, 0x2f, 0xfd)
	idx := bytes.Index(file, marker)
	require.NotEqual(t, -1, idx, "compressed zstd buffer not found")
	require.Equal(t, -1, bytes.Index(file[idx+len(marker):], marker), "compressed zstd buffer is not unique")
	compressed := file[idx+8:]
	require.GreaterOrEqual(t, len(compressed), len(payload))
	copy(compressed, payload)
	return file
}

func TestArrowQueryRejectsCraftedZstdFrame(t *testing.T) {
	svc := ProvideService()
	for i, payload := range craftedZstdFrames() {
		t.Run(fmt.Sprintf("frame-%d", i), func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(arrowFileWithZstdPayload(t, payload))
			resp, err := svc.QueryData(context.Background(), &backend.QueryDataRequest{
				Queries: []backend.DataQuery{{
					RefID:     "A",
					QueryType: string(kinds.TestDataQueryTypeArrow),
					JSON: []byte(fmt.Sprintf(
						`{"scenarioId":"arrow","stringInput":%q}`, encoded)),
				}},
			})
			require.Error(t, err)
			require.Nil(t, resp)

			// External plugins return the same bytes through UnmarshalArrowFrame
			// (QueryData and QueryChunkedData). Same decoder, same requirement.
			_, uerr := data.UnmarshalArrowFrame(arrowFileWithZstdPayload(t, payload))
			require.Error(t, uerr)
		})
	}
}
