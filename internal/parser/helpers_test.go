package parser

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func init() {
	DisableMavenSleepForTesting()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockHTTP(t *testing.T, handler roundTripFunc) {
	t.Helper()
	old := SetHTTPClient(&http.Client{Transport: handler})
	t.Cleanup(func() { SetHTTPClient(old) })
}

func response(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func writeFixture(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
