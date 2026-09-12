package apple

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestDevicePushOutcomeKeepsPrivateCausesOutOfStorage(t *testing.T) {
	const secret = "owned-private-push-canary"
	for _, tc := range []struct {
		err    error
		status string
	}{
		{nil, "accepted"},
		{&url.Error{Op: "Post", URL: "https://push.example.test/3/device/" + secret, Err: errors.New("dial failed")}, "failed"},
		{errors.New("decryption failed: " + secret), "failed"},
		{&PushError{Status: 500, Reason: secret}, "failed"},
		{fmt.Errorf("%s: %w", secret, &PushError{Status: 400, Reason: "BadDeviceToken"}), "invalid_token"},
		{&PushError{Status: 410, Reason: secret}, "invalid_token"},
		{&PushError{Status: 400, Reason: "DeviceTokenNotForTopic"}, "invalid_token"},
	} {
		status, detail := devicePushOutcome(tc.err)
		if status != tc.status || (tc.err == nil) != (detail == "") {
			t.Fatal("push outcome lost delivery classification", status, tc.status)
		}
		if strings.Contains(detail, secret) || strings.Contains(detail, "push.example.test") {
			t.Error("push outcome retained a private transport or response detail", status)
		}
	}
}
