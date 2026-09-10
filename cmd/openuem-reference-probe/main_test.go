package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReferenceProbeCommand(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--help"}, &output); err != nil || !strings.Contains(output.String(), "Usage:") {
		t.Fatal("command help failed", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	output.Reset()
	if err := run([]string{"--mode", "http", "--address", server.URL + "/healthz", "--timeout", "1s"}, &output); err != nil || output.String() != "{\"ready\":true}\n" {
		t.Fatal("command readiness result failed", err)
	}
	for _, arguments := range [][]string{{"--unknown=synthetic-secret"}, {"--mode", "http", "synthetic-secret"}, {"--timeout", "0s"}, {"--timeout", "2m"}} {
		output.Reset()
		err := run(arguments, &output)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(output.String(), "synthetic-secret") {
			t.Fatal("invalid arguments accepted or echoed")
		}
	}
	if err := run([]string{"--help"}, nil); err == nil {
		t.Fatal("nil output accepted")
	}
}
