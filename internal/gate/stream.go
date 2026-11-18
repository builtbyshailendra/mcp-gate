package gate

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// newSSEFilter passes a text/event-stream through, rewriting each event's
// data with fn. It works one event at a time, so a stream that stays open for
// hours (MCP's notification streams do) is never held back.
func newSSEFilter(src io.ReadCloser, maxEvent int64, fn func([]byte) []byte) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(filterEvents(src, pw, maxEvent, fn))
	}()
	return &sseBody{PipeReader: pr, src: src}
}

type sseBody struct {
	*io.PipeReader
	src io.ReadCloser
}

// Close stops the copy: closing the pipe unblocks the writer, closing the
// upstream body unblocks the reader.
func (b *sseBody) Close() error {
	_ = b.PipeReader.Close()
	return b.src.Close()
}

var errEventTooBig = errors.New("server-sent event is larger than the gate's limit")

// sseLines splits a stream into lines the way the SSE spec does: a line ends
// at CRLF, LF, or a lone CR. Splitting only on LF (the first version did)
// lets the gate and the client see different events in the same bytes;
// fuzzing found that. terminated reports whether the last line had an end.
func sseLines(terminated *bool) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		for i, b := range data {
			switch b {
			case '\n':
				*terminated = true
				return i + 1, data[:i], nil
			case '\r':
				if i+1 < len(data) {
					*terminated = true
					if data[i+1] == '\n' {
						return i + 2, data[:i], nil
					}
					return i + 1, data[:i], nil
				}
				if atEOF {
					*terminated = true
					return i + 1, data[:i], nil
				}
				return 0, nil, nil // a CR at the end of the buffer: is LF next?
			}
		}
		if atEOF && len(data) > 0 {
			*terminated = false
			return len(data), data, nil
		}
		return 0, nil, nil
	}
}

func filterEvents(src io.Reader, dst io.Writer, maxEvent int64, fn func([]byte) []byte) error {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64<<10), int(min(maxEvent, 1<<30)))
	var terminated bool
	sc.Split(sseLines(&terminated))
	var (
		fields [][]byte // id:, event:, retry: and comment lines
		data   [][]byte // the values of data lines
		size   int64
	)
	emit := func(end bool) error {
		var buf bytes.Buffer
		for _, f := range fields {
			buf.Write(f)
			buf.WriteByte('\n')
		}
		if data != nil {
			for _, line := range bytes.Split(fn(bytes.Join(data, []byte("\n"))), []byte("\n")) {
				buf.WriteString("data: ")
				buf.Write(line)
				buf.WriteByte('\n')
			}
		}
		if end {
			buf.WriteByte('\n')
		}
		fields, data, size = nil, nil, 0
		_, err := dst.Write(buf.Bytes())
		return err
	}
	for sc.Scan() {
		line := sc.Bytes()
		size += int64(len(line)) + 1
		if size > maxEvent {
			return errEventTooBig
		}
		switch {
		case len(line) == 0 && terminated: // a blank line ends the event
			if err := emit(true); err != nil {
				return err
			}
		case bytes.Equal(line, []byte("data")): // a field with no colon has an empty value
			data = append(data, []byte{})
		case bytes.HasPrefix(line, []byte("data:")):
			v := bytes.TrimPrefix(line[len("data:"):], []byte(" "))
			data = append(data, bytes.Clone(v))
		default:
			fields = append(fields, bytes.Clone(line))
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return errEventTooBig
		}
		return err
	}
	if fields != nil || data != nil {
		// An event cut off by the end of the stream. Clients drop it; pass
		// it on unterminated so they still can.
		return emit(false)
	}
	return nil
}
