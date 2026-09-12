package windows

import (
	"bytes"
	"errors"
)

var ErrUnenrollmentRequest = errors.New("invalid or conflicting native Windows disconnection request")

// The lifecycle-only encoder never opens protected enrollment roots to custom
// CSP requests. The ProviderID is taken from the stored enrollment configuration.
func encodeUnenrollmentRequest(options EnrollmentOptions) ([]byte, error) {
	if options.validate() != nil {
		return nil, ErrUnenrollmentRequest
	}
	command := SyncMLCommand{Kind: "Exec", ID: "1", Items: []SyncMLItem{{Target: &SyncMLLocation{URI: "./Device/Vendor/MSFT/DMClient/Unenroll"}, Meta: &SyncMLMeta{Format: "chr"}, Data: &SyncMLData{Text: options.ProviderID}}}}
	return EncodeSyncML(&SyncMLMessage{Header: SyncMLHeader{SessionID: "openuem-unenrollment-v1", MessageID: "1", Target: SyncMLLocation{URI: "urn:openuem:windows:unenrollment"}, Source: SyncMLLocation{URI: "urn:openuem:console"}}, Commands: []SyncMLCommand{command}, Final: true})
}

func decodeUnenrollmentRequest(data []byte) (SyncMLCommand, error) {
	message, err := ParseSyncML(data)
	if err != nil || len(data) > 8192 || len(message.Commands) != 1 || len(message.Commands[0].Items) != 1 || message.Commands[0].Items[0].Data == nil {
		return SyncMLCommand{}, ErrAuthoritySecret
	}
	// This comparison verifies the entire private storage envelope and command;
	// the owning request subsequently binds the provider to the enrolled options.
	provider := message.Commands[0].Items[0].Data.Text
	options := EnrollmentOptions{ManagementURL: "https://unenrollment.invalid/syncml", ProviderID: provider, DisplayName: "Unenrollment"}
	canonical, err := encodeUnenrollmentRequest(options)
	if err != nil || !bytes.Equal(canonical, data) {
		return SyncMLCommand{}, ErrAuthoritySecret
	}
	return message.Commands[0], nil
}
