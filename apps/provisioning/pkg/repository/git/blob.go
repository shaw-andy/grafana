package git

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/grafana/nanogit"
	"github.com/grafana/nanogit/protocol"
	"github.com/grafana/nanogit/protocol/hash"
)

// uploadPacker is satisfied by the nanogit HTTP client, which embeds the raw
// protocol client.
type uploadPacker interface {
	UploadPack(ctx context.Context, data io.Reader) (io.ReadCloser, error)
}

// blobTooLargeError reports a blob whose packfile header declares more bytes
// than the caller allows. The body is never transferred or inflated.
type blobTooLargeError struct {
	size int64
	max  int64
}

func (e *blobTooLargeError) Error() string {
	return fmt.Sprintf("blob is %d bytes; max allowed is %d bytes", e.size, e.max)
}

var errBlobResponseTooLarge = errors.New("blob fetch response exceeded the size limit")

// fetchBlobLimited fetches a single blob by hash and refuses it from the
// packfile object header, before the body is read, when it is larger than
// maxBytes. The returned content is verified against blobID.
func fetchBlobLimited(ctx context.Context, up uploadPacker, blobID hash.Hash, maxBytes int64) ([]byte, error) {
	req, err := protocol.FormatPacks(
		protocol.PackLine("command=fetch\n"),
		protocol.PackLine("object-format=sha1\n"),
		protocol.DelimeterPacket,
		protocol.PackLine("no-progress\n"),
		protocol.PackLine(fmt.Sprintf("want %s\n", blobID.String())),
		protocol.PackLine("done\n"),
		protocol.FlushPacket,
	)
	if err != nil {
		return nil, fmt.Errorf("format fetch request: %w", err)
	}

	body, err := up.UploadPack(ctx, bytes.NewReader(req))
	if err != nil {
		if strings.Contains(err.Error(), "not our ref") {
			return nil, nanogit.NewObjectNotFoundError(blobID)
		}
		return nil, fmt.Errorf("fetch blob %s: %w", blobID.String(), err)
	}
	defer func() { _ = body.Close() }()

	// A blob within maxBytes needs at most a few bytes per deflate block and
	// pkt-line on top of its own size; anything beyond this is not a valid
	// response for it.
	wire := &limitedReader{r: body, remaining: maxBytes + maxBytes/16 + 64*1024}
	parser := protocol.NewParser(wire)

	if err := skipToPackfileSection(parser); err != nil {
		if strings.Contains(err.Error(), "not our ref") {
			return nil, nanogit.NewObjectNotFoundError(blobID)
		}
		return nil, fmt.Errorf("fetch blob %s: %w", blobID.String(), err)
	}

	pack := bufio.NewReader(protocol.NewMultiplexedReader(ctx, parser))
	data, err := readSingleBlobFromPack(pack, maxBytes)
	if err != nil {
		var tooLarge *blobTooLargeError
		if errors.As(err, &tooLarge) {
			return nil, err
		}
		return nil, fmt.Errorf("read blob %s: %w", blobID.String(), err)
	}

	got, err := protocol.Object(crypto.SHA1, protocol.ObjectTypeBlob, data)
	if err != nil {
		return nil, fmt.Errorf("hash blob %s: %w", blobID.String(), err)
	}
	if !got.Is(blobID) {
		return nil, fmt.Errorf("fetch blob %s: server returned object %s", blobID.String(), got.String())
	}

	return data, nil
}

func skipToPackfileSection(parser *protocol.Parser) error {
	for {
		line, err := parser.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("response has no packfile section")
			}
			return err
		}
		if strings.TrimSpace(string(line)) == "packfile" {
			return nil
		}
	}
}

func readSingleBlobFromPack(pack *bufio.Reader, maxBytes int64) ([]byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(pack, header[:]); err != nil {
		return nil, fmt.Errorf("read packfile header: %w", err)
	}
	if !bytes.Equal(header[:4], []byte("PACK")) {
		return nil, protocol.ErrNoPackfileSignature
	}
	if version := binary.BigEndian.Uint32(header[4:8]); version != 2 && version != 3 {
		return nil, fmt.Errorf("version %d: %w", version, protocol.ErrUnsupportedPackfileVersion)
	}
	if count := binary.BigEndian.Uint32(header[8:12]); count != 1 {
		return nil, fmt.Errorf("expected 1 object in packfile, got %d", count)
	}

	b, err := pack.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read object header: %w", err)
	}
	objType := protocol.ObjectType((b >> 4) & 0b111)
	size := int64(b & 0b1111)
	for shift := 4; b&0x80 != 0; shift += 7 {
		if shift > 56 {
			return nil, errors.New("object size header overflows")
		}
		if b, err = pack.ReadByte(); err != nil {
			return nil, fmt.Errorf("read object header: %w", err)
		}
		size |= int64(b&0x7f) << shift
	}

	if objType != protocol.ObjectTypeBlob {
		return nil, fmt.Errorf("expected blob object, got %s", objType)
	}
	if size > maxBytes {
		return nil, &blobTooLargeError{size: size, max: maxBytes}
	}
	if size > protocol.MaxUnpackedObjectSize {
		return nil, fmt.Errorf("%w (%d bytes)", protocol.ErrObjectTooLarge, size)
	}

	zr, err := zlib.NewReader(pack)
	if err != nil {
		return nil, fmt.Errorf("inflate blob: %w", err)
	}
	defer func() { _ = zr.Close() }()

	data := make([]byte, size)
	if _, err := io.ReadFull(zr, data); err != nil {
		return nil, fmt.Errorf("inflate blob: %w", err)
	}
	var extra [1]byte
	n, err := zr.Read(extra[:])
	if n != 0 {
		return nil, protocol.ErrInflatedDataIncorrectSize
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("inflate blob: %w", err)
	}

	return data, nil
}

type limitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errBlobResponseTooLarge
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}
