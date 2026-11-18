package gate

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func upper(b []byte) []byte { return bytes.ToUpper(b) }

func TestFilterEvents(t *testing.T) {
	in := ": keep-alive comment\n" +
		"id: 1\r\nevent: message\r\ndata: {\"a\":1}\r\n\r\n" +
		"data: line one\ndata:line two\n\n" +
		"data: lone\rdata: cr\r\r" + // a lone CR ends a line too
		"data\n\n" + // a field with no colon: empty data
		"retry: 500\n\n" +
		"data: cut off"
	want := ": keep-alive comment\n" +
		"id: 1\nevent: message\ndata: {\"A\":1}\n\n" +
		"data: LINE ONE\ndata: LINE TWO\n\n" +
		"data: LONE\ndata: CR\n\n" +
		"data: \n\n" +
		"retry: 500\n\n" +
		"data: CUT OFF\n"
	var out bytes.Buffer
	if err := filterEvents(strings.NewReader(in), &out, 1<<20, upper); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("got\n%q\nwant\n%q", out.String(), want)
	}
}

func TestFilterEventsLimit(t *testing.T) {
	in := "data: " + strings.Repeat("x", 100) + "\n\n"
	err := filterEvents(strings.NewReader(in), io.Discard, 50, upper)
	if !errors.Is(err, errEventTooBig) {
		t.Fatalf("err = %v, want errEventTooBig", err)
	}
}

// The filter must hand each event on as soon as it's complete, not when the
// stream ends: MCP streams can stay open for the life of a session.
func TestSSEFilterDoesNotWaitForTheEnd(t *testing.T) {
	src, w := io.Pipe()
	body := newSSEFilter(src, 1<<20, upper)
	defer body.Close()
	go func() { _, _ = io.WriteString(w, "data: first\n\n") }()

	got := make(chan string, 1)
	go func() {
		br := bufio.NewReader(body)
		line, _ := br.ReadString('\n')
		got <- line
	}()
	select {
	case line := <-got:
		if line != "data: FIRST\n" {
			t.Fatalf("got %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first event was held back")
	}
	_ = w.Close()
}
