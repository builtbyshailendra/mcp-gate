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

func filterEvents(src io.Reader, dst io.Writer, maxEvent int64, fn func([]byte) []byte) error {
	br := bufio.NewReaderSize(src, 64<<10)
	var (
		fields [][]byte // id:, event:, retry: and comment lines, kept as received
		data   [][]byte // the values of data: lines
		size   int64
	)
	emit := func(terminated bool) error {
		var buf bytes.Buffer
		for _, f := range fields {
			buf.Write(f)
		}
		if data != nil {
			for _, line := range bytes.Split(fn(bytes.Join(data, []byte("\n"))), []byte("\n")) {
				buf.WriteString("data: ")
				buf.Write(line)
				buf.WriteByte('\n')
			}
		}
		if terminated {
			buf.WriteByte('\n')
		}
		fields, data, size = nil, nil, 0
		_, err := dst.Write(buf.Bytes())
		return err
	}
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			size += int64(len(line))
			if size > maxEvent {
				return errEventTooBig
			}
			content := bytes.TrimRight(line, "\r\n")
			switch {
			case len(content) == 0 && err == nil: // a blank line ends the event
				if werr := emit(true); werr != nil {
					return werr
				}
			case bytes.HasPrefix(content, []byte("data:")):
				v := bytes.TrimPrefix(content[len("data:"):], []byte(" "))
				data = append(data, bytes.Clone(v))
			default:
				fields = append(fields, bytes.Clone(line))
			}
		}
		if err != nil {
			if fields != nil || data != nil {
				// An event cut off by the end of the stream. Clients drop
				// it; pass it on unterminated so they still can.
				if werr := emit(false); werr != nil {
					return werr
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
