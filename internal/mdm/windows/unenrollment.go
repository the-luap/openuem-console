package windows

import "strconv"

const windowsUnenrollmentAlertType = "com.microsoft:mdm.unenrollment.userrequest"

// Windows sends this best-effort notification as a new first package before
// cleanup. It cannot require another round trip or prove cleanup completed.
func syncMLUnenrollmentAlert(request *SyncMLMessage) (*SyncMLCommand, error) {
	var found *SyncMLCommand
	var visit func([]SyncMLCommand, bool) error
	visit = func(commands []SyncMLCommand, nested bool) error {
		for n := range commands {
			c := &commands[n]
			for _, item := range c.Items {
				if item.Meta == nil || item.Meta.Type != windowsUnenrollmentAlertType {
					continue
				}
				if found != nil || nested || c.Kind != "Alert" || c.Data == nil || c.Data.Text != "1226" || c.Data.XML != "" || c.Data.OriginalError != "" || c.Meta != nil || len(c.Items) != 1 || item.MoreData || item.Source != nil || item.Target != nil || item.Data == nil || item.Data.Text != "1" || item.Data.XML != "" || item.Data.OriginalError != "" {
					return ErrSyncMLSession
				}
				meta := *item.Meta
				meta.Type, meta.Format = "", ""
				if item.Meta.Format != "int" || meta.Mark != "" || meta.Version != "" || meta.NextNonce != "" || meta.Size != nil || meta.MaxMessageSize != nil || meta.MaxObjectSize != nil || len(meta.EMI) != 0 {
					return ErrSyncMLSession
				}
				found = c
			}
			if err := visit(c.Commands, true); err != nil {
				return err
			}
		}
		return nil
	}
	if request == nil {
		return nil, ErrSyncMLSession
	}
	if err := visit(request.Commands, false); err != nil {
		return nil, err
	}
	if found == nil {
		return nil, nil
	}
	if request.Header.MessageID != "1" || !request.Final || request.Header.ResponseURI != "" {
		return nil, ErrSyncMLSession
	}
	// Only accompanying session-start alerts and bounded DevInfo reports can
	// share this terminal notification. No command results or mutations run here.
	for _, c := range request.Commands {
		if c.ID == found.ID {
			continue
		}
		switch c.Kind {
		case "Replace":
			if !syncMLTextMetadata(c.Meta) {
				return nil, ErrSyncMLSession
			}
			for _, item := range c.Items {
				if item.Source == nil || !syncMLDeviceInfoURI(item.Source.URI) || item.Target != nil || item.MoreData || item.Data == nil || item.Data.XML != "" || item.Data.OriginalError != "" || len(item.Data.Text) > maxSyncMLDeviceInfoBytes || !syncMLTextMetadata(item.Meta) {
					return nil, ErrSyncMLSession
				}
			}
		case "Alert":
			if c.Data == nil || (c.Data.Text != "1200" && c.Data.Text != "1201" && c.Data.Text != "1224") {
				return nil, ErrSyncMLSession
			}
		default:
			return nil, ErrSyncMLSession
		}
	}
	return found, nil
}

func unenrollmentResponse(identity ManagementDeviceIdentity, options EnrollmentOptions, request *SyncMLMessage, alert *SyncMLCommand, secrets *syncMLBootstrapSecrets, nonces syncMLDeviceNonces) ([]byte, error) {
	if !sameEnrollmentEndpoint(request.Header.Target.URI, options.ManagementURL) || (request.Header.Target.Name != "" && request.Header.Target.Name != options.ProviderID) || !syncMLClientDigestValid(identity, request, secrets.ClientSecret, nonces.ClientNonce) {
		return nil, ErrSyncMLSession
	}
	session := &syncMLSession{Phase: "authenticating", State: syncMLSessionState{DeviceInfo: map[string]string{}, IncompleteInfo: map[string]bool{}}}
	response := &SyncMLMessage{Header: SyncMLHeader{SessionID: request.Header.SessionID, MessageID: "1", Target: request.Header.Source, Source: SyncMLLocation{URI: options.ManagementURL, Name: options.ProviderID}}, Final: true}
	response.Header.Target.Name = identity.DeviceID
	syncMLStatus(response, "1", "0", "SyncHdr", "212")
	for _, command := range request.Commands {
		if command.ID == alert.ID {
			syncMLStatus(response, "1", command.ID, "Alert", "200")
			continue
		}
		if err := processSyncMLClientCommands(session, &SyncMLMessage{Header: request.Header, Commands: []SyncMLCommand{command}, Final: true}, response, false); err != nil {
			return nil, err
		}
	}
	digest, err := syncMLDigest(options.ProviderID, secrets.ServerSecret, nonces.ServerNonce)
	if err != nil {
		return nil, err
	}
	response.Header.Credential = &SyncMLCredential{Digest: digest}
	for n := range response.Commands {
		response.Commands[n].ID = strconv.Itoa(n + 1)
	}
	encoded, err := EncodeSyncML(response)
	if err != nil {
		return nil, err
	}
	maximum := uint64(MaxSyncMLBytes)
	if request.Header.Meta != nil && request.Header.Meta.MaxMessageSize != nil {
		maximum = min(maximum, *request.Header.Meta.MaxMessageSize)
	}
	if uint64(len(encoded)) > maximum {
		return nil, ErrSyncMLMessageSize
	}
	return encoded, nil
}
