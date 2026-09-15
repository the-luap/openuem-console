package common

import (
	"context"
	"io"
	"net/http"
	"time"
)

// queryReleasesEndpoint retains the existing release request behavior while
// allowing foreground shutdown to cancel startup checks and scheduled requests.
func (w *Worker) queryReleasesEndpoint(url string) ([]byte, error) {
	ctx := w.Context
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "openuem-console")
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}
