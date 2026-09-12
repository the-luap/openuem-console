package apple

import (
	"os"
	"testing"
	"time"
)

// Opt-in interactive fixture uses the real TLS handler and an isolated schema.
// Write <path>.stop to end the preview and remove all fixture database data.
func TestEnrollmentBrowserFixture(t *testing.T) {
	path := os.Getenv("OPENUEM_ENROLLMENT_BROWSER_FIXTURE")
	if path == "" {
		t.Skip("set OPENUEM_ENROLLMENT_BROWSER_FIXTURE to a private temporary path for browser acceptance")
	}
	_, _, invitation, _ := portalFixture(t)
	if err := os.WriteFile(path, []byte(invitation.URL), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path); _ = os.Remove(path + ".stop") })
	t.Log("Enrollment browser fixture is ready; its private URL is in the configured file")
	deadline := time.NewTimer(8 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("browser fixture timed out; its isolated schema has been removed")
		case <-ticker.C:
			if _, err := os.Stat(path + ".stop"); err == nil {
				return
			}
		}
	}
}
