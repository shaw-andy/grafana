package utils

import (
	"fmt"
	"io"
)

// MaxResponseBodyBytes caps how much of an Azure response body is buffered in
// memory for resource, metadata, and health-check calls.
const MaxResponseBodyBytes int64 = 32 << 20

var ErrResponseTooLarge = fmt.Errorf("azure response body exceeded %d bytes", MaxResponseBodyBytes)

// LimitReader returns a reader that fails with ErrResponseTooLarge once more
// than MaxResponseBodyBytes have been read from r, instead of silently
// truncating like io.LimitReader.
func LimitReader(r io.Reader) io.Reader {
	return &limitedReader{r: io.LimitReader(r, MaxResponseBodyBytes+1), remaining: MaxResponseBodyBytes}
}

// LimitReadCloser is LimitReader for response bodies; Close closes rc.
func LimitReadCloser(rc io.ReadCloser) io.ReadCloser {
	return struct {
		io.Reader
		io.Closer
	}{LimitReader(rc), rc}
}

// ReadAllLimited reads r to EOF, failing with ErrResponseTooLarge if it holds
// more than MaxResponseBodyBytes.
func ReadAllLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(LimitReader(r))
	if err != nil {
		return nil, err
	}
	return body, nil
}

type limitedReader struct {
	r         io.Reader
	remaining int64
	err       error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.err != nil {
		return 0, l.err
	}
	n, err := l.r.Read(p)
	if int64(n) > l.remaining {
		n = int(l.remaining)
		l.remaining = 0
		l.err = ErrResponseTooLarge
		return n, l.err
	}
	l.remaining -= int64(n)
	return n, err
}
