package testdatasource

import (
	"errors"
	"fmt"

	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/grafana/grafana-plugin-sdk-go/data"
)

var (
	errArrowAllocationLimit = errors.New("arrow data expands beyond its encoded size")
	errArrowCellLimit       = errors.New("arrow data declares more values than its encoded size can hold")
)

// limitedAllocator caps the total bytes arrow-go may allocate while decoding.
// arrow-go sizes decompressed IPC buffers from a length prefix stored in the
// input itself, so without a cap that prefix alone decides the allocation.
// The memory.Allocator interface cannot return errors, so exceeding the cap
// panics; unmarshalArrowFrame turns that panic into an error.
type limitedAllocator struct {
	mem       memory.Allocator
	remaining int
}

func (a *limitedAllocator) reserve(size int) {
	if size < 0 || size > a.remaining {
		panic(errArrowAllocationLimit)
	}
	a.remaining -= size
}

func (a *limitedAllocator) Allocate(size int) []byte {
	a.reserve(size)
	return a.mem.Allocate(size)
}

// Reallocate charges the full size because the Go allocator copies into a new
// slice rather than growing in place.
func (a *limitedAllocator) Reallocate(size int, b []byte) []byte {
	a.reserve(size)
	return a.mem.Reallocate(size, b)
}

func (a *limitedAllocator) Free(b []byte) {
	a.mem.Free(b)
}

// unmarshalArrowFrame decodes an Arrow IPC file into a single frame without
// letting values declared inside the file drive memory use. Buffers are read
// in place from b, so arrow-go only allocates when decompressing, and those
// allocations may not exceed len(b) in total. Every column type the SDK
// converts stores at least one bit per row, so a well-formed file cannot hold
// more than 8*len(b) values; record batches that alias the same bytes, through
// repeated footer entries or shared buffers, are rejected by that limit.
func unmarshalArrowFrame(b []byte) (frame *data.Frame, err error) {
	defer func() {
		if r := recover(); r != nil {
			frame = nil
			if rErr, ok := r.(error); ok {
				err = fmt.Errorf("could not read arrow data: %w", rErr)
				return
			}
			err = fmt.Errorf("could not read arrow data: %v", r)
		}
	}()

	mem := &limitedAllocator{mem: memory.NewGoAllocator(), remaining: len(b)}
	fr, err := ipc.NewMappedFileReader(b, ipc.WithAllocator(mem))
	if err != nil {
		return nil, err
	}
	defer func() { _ = fr.Close() }()

	schema := fr.Schema()
	numFields := int64(schema.NumFields())
	remainingCells := int64(len(b)) * 8

	if fr.NumRecords() == 0 {
		empty := array.NewRecordBuilder(memory.NewGoAllocator(), schema)
		defer empty.Release()
		rec := empty.NewRecordBatch()
		defer rec.Release()
		return data.FromArrowRecord(rec)
	}

	for i := 0; i < fr.NumRecords(); i++ {
		rec, err := fr.RecordBatch(i)
		if err != nil {
			return nil, err
		}
		if rec.NumRows() < 0 || (numFields > 0 && rec.NumRows() > remainingCells/numFields) {
			return nil, errArrowCellLimit
		}
		remainingCells -= rec.NumRows() * numFields

		next, err := data.FromArrowRecord(rec)
		if err != nil {
			return nil, err
		}
		if frame == nil {
			frame = next
			continue
		}
		appendFrameRows(frame, next)
	}
	return frame, nil
}

func appendFrameRows(dst, src *data.Frame) {
	for i, field := range src.Fields {
		for row := 0; row < field.Len(); row++ {
			dst.Fields[i].Append(field.At(row))
		}
	}
}
