package windows

import (
	"strconv"
	"strings"
)

var syncMLRequiredDeviceInfo = []string{"./DevInfo/DevId", "./DevInfo/Man", "./DevInfo/Mod", "./DevInfo/DmV", "./DevInfo/Lang"}

func syncMLDeviceInfoURI(uri string) bool {
	for _, known := range syncMLRequiredDeviceInfo {
		if uri == known {
			return true
		}
	}
	return false
}

func syncMLResponseHeader(identity ManagementDeviceIdentity, options EnrollmentOptions, session *syncMLSession, messageID string) SyncMLHeader {
	maximumMessage, maximumObject := uint64(MaxSyncMLBytes), uint64(MaxCSPResultBytes)
	return SyncMLHeader{SessionID: session.WireID, MessageID: messageID,
		Target: SyncMLLocation{URI: session.State.SourceURI, Name: identity.DeviceID},
		Source: SyncMLLocation{URI: options.ManagementURL, Name: options.ProviderID},
		Meta:   &SyncMLMeta{MaxMessageSize: &maximumMessage, MaxObjectSize: &maximumObject}}
}

func syncMLStatus(response *SyncMLMessage, requestMessageID, commandID, commandName, code string) *SyncMLCommand {
	response.Commands = append(response.Commands, SyncMLCommand{Kind: "Status", ID: strconv.Itoa(len(response.Commands) + 1), MessageRef: requestMessageID, CommandRef: commandID, CommandName: commandName, Data: &SyncMLData{Text: code}})
	return &response.Commands[len(response.Commands)-1]
}

func syncMLChallenge(nonce string) *SyncMLMeta {
	return &SyncMLMeta{Format: "b64", Type: syncMLDigestType, NextNonce: nonce}
}

func syncMLRejectCommands(response *SyncMLMessage, messageID string, commands []SyncMLCommand, code string) {
	for _, command := range commands {
		syncMLStatus(response, messageID, command.ID, command.Kind, code)
		syncMLRejectCommands(response, messageID, command.Commands, code)
	}
}

func syncMLClientDigestValid(identity ManagementDeviceIdentity, request *SyncMLMessage, secret, nonce string) bool {
	return request.Header.Credential != nil && (request.Header.Source.Name == "" || request.Header.Source.Name == identity.DeviceID) && verifySyncMLDigest(identity.DeviceID, secret, nonce, request.Header.Credential.Digest) == nil
}

// advanceSyncMLSession only mutates transaction-local protected state. Its caller
// must encrypt and commit all state, response and audit before returning bytes.
func advanceSyncMLSession(identity ManagementDeviceIdentity, options EnrollmentOptions, record *syncMLDeviceRecord, session *syncMLSession, request *SyncMLMessage, secrets *syncMLBootstrapSecrets) (*SyncMLMessage, []string, error) {
	if request == nil || secrets == nil || secrets.validate() != nil || syncMLTerminal(session.Phase) || request.Header.SessionID != session.WireID || request.Header.Source.URI != session.State.SourceURI || !sameEnrollmentEndpoint(request.Header.Target.URI, options.ManagementURL) || (request.Header.Target.Name != "" && request.Header.Target.Name != options.ProviderID) || request.Header.ResponseURI != "" {
		return nil, nil, ErrSyncMLSession
	}
	messageID, err := strconv.Atoi(request.Header.MessageID)
	if err != nil || messageID != session.LastMessage+1 || messageID > maxSyncMLSessionMessages {
		return nil, nil, ErrSyncMLSession
	}
	state := &session.State
	if request.Header.Meta != nil && request.Header.Meta.MaxMessageSize != nil {
		state.MaximumResponseBytes = min(*request.Header.Meta.MaxMessageSize, uint64(MaxSyncMLBytes))
	}
	if request.Header.Meta != nil && request.Header.Meta.MaxObjectSize != nil {
		state.MaximumResponseObjectBytes = min(*request.Header.Meta.MaxObjectSize, uint64(MaxCSPRequestBytes))
	}
	response := &SyncMLMessage{Header: syncMLResponseHeader(identity, options, session, request.Header.MessageID), Final: true}
	events := []string{}
	clientValid := state.ClientAuthenticated && request.Header.Credential == nil && (request.Header.Source.Name == "" || request.Header.Source.Name == identity.DeviceID)
	if request.Header.Credential != nil {
		clientValid = syncMLClientDigestValid(identity, request, secrets.ClientSecret, state.ClientNonce)
	}
	if !clientValid {
		code := "401"
		if request.Header.Credential == nil {
			code = "407"
		}
		if state.ClientChallenges == 0 {
			nonce, err := newSyncMLNonce()
			if err != nil {
				return nil, nil, err
			}
			state.ClientNonce, record.Nonces.ClientNonce = nonce, nonce
			state.ClientChallenges++
			state.ClientAuthenticated = false
			session.Phase = "authenticating"
			events = append(events, "session.challenged")
		} else {
			session.Phase = "failed"
			events = append(events, "session.failed")
		}
		syncMLStatus(response, request.Header.MessageID, "0", "SyncHdr", code).Challenge = syncMLChallenge(state.ClientNonce)
		syncMLRejectCommands(response, request.Header.MessageID, request.Commands, code)
		if err := finishSyncMLResponse(options, session, response, secrets); err != nil {
			return nil, nil, err
		}
		return response, events, nil
	}
	justAuthenticated := !state.ClientAuthenticated
	state.ClientAuthenticated = true
	headerStatus := syncMLStatus(response, request.Header.MessageID, "0", "SyncHdr", "212")
	if justAuthenticated {
		nonce, err := newSyncMLNonce()
		if err != nil {
			return nil, nil, err
		}
		record.Nonces.ClientNonce = nonce
		headerStatus.Challenge = syncMLChallenge(nonce)
	}
	serverRetry := false
	if session.LastMessage > 0 {
		retry, err := processSyncMLServerAuthentication(record, session, request)
		if err != nil {
			return nil, nil, err
		}
		serverRetry = retry
	} else {
		for _, command := range request.Commands {
			if command.Kind == "Status" && command.CommandName == "SyncHdr" {
				return nil, nil, ErrSyncMLSession
			}
		}
	}
	if state.ServerVerified && session.Phase == "authenticating" {
		session.Phase = "active"
		events = append(events, "session.authenticated")
	}
	if state.CSP != nil {
		remaining, err := processCSPResponses(session, request, response)
		if err != nil {
			return nil, nil, err
		}
		request = remaining
		if serverRetry {
			state.CSP.StopReason = "server_authentication_retry"
			session.Phase = "failed"
		}
	}
	if session.Phase == "failed" {
		syncMLAbortResponse(response)
		events = append(events, "session.failed")
	} else {
		if err := processSyncMLClientCommands(session, request, response, serverRetry); err != nil {
			return nil, nil, err
		}
		if session.Phase == "aborted" {
			events = append(events, "session.aborted")
		} else if session.Phase == "failed" {
			syncMLAbortResponse(response)
			events = append(events, "session.failed")
		} else if request.Final && state.Probe != nil && state.ServerVerified && (state.CSP == nil || cspOutcome(state.CSP) != "") && (state.Probe.Status == "200" && state.Probe.HasResult && !state.Probe.MoreData || syncMLProbeFailed(state.Probe)) {
			session.Phase = "completed"
			events = append(events, "session.completed")
		} else if messageID == maxSyncMLSessionMessages {
			session.Phase = "failed"
			syncMLAbortResponse(response)
			events = append(events, "session.failed")
		} else if request.Final && state.Probe == nil {
			for _, uri := range syncMLRequiredDeviceInfo {
				if state.DeviceInfo[uri] == "" || state.IncompleteInfo[uri] {
					return nil, nil, ErrSyncMLSession
				}
			}
			id := strconv.Itoa(len(response.Commands) + 1)
			response.Commands = append(response.Commands, SyncMLCommand{Kind: "Get", ID: id, Items: []SyncMLItem{{Target: &SyncMLLocation{URI: "./DevInfo/DevId"}}}})
			state.Probe = &syncMLIdentityProbe{MessageID: request.Header.MessageID, CommandID: id}
		} else {
			response.Commands = append(response.Commands, SyncMLCommand{Kind: "Alert", ID: strconv.Itoa(len(response.Commands) + 1), Data: &SyncMLData{Text: "1222"}})
			response.Final = false
		}
	}
	if err := finishSyncMLResponse(options, session, response, secrets); err != nil {
		return nil, nil, err
	}
	return response, events, nil
}

func syncMLAbortResponse(response *SyncMLMessage) {
	response.Commands = append(response.Commands, SyncMLCommand{Kind: "Alert", ID: strconv.Itoa(len(response.Commands) + 1), Data: &SyncMLData{Text: "1223"}})
}

func finishSyncMLResponse(options EnrollmentOptions, session *syncMLSession, response *SyncMLMessage, secrets *syncMLBootstrapSecrets) error {
	state := &session.State
	state.LastServerCredential = !state.ServerAuthenticated
	if state.LastServerCredential {
		digest, err := syncMLDigest(options.ProviderID, secrets.ServerSecret, state.ServerNonce)
		if err != nil {
			return err
		}
		response.Header.Credential = &SyncMLCredential{Digest: digest}
	}
	state.LastResponse = assignSyncMLResponseIDs(session, response)
	session.LastMessage++
	return nil
}

func assignSyncMLResponseIDs(session *syncMLSession, response *SyncMLMessage) []syncMLSentCommand {
	var sent []syncMLSentCommand
	var assign func([]SyncMLCommand)
	assign = func(commands []SyncMLCommand) {
		for n := range commands {
			command := &commands[n]
			id := syncMLResponseCommandID(session, response.Header.MessageID, len(sent))
			if session.State.Probe != nil && session.State.Probe.MessageID == response.Header.MessageID && session.State.Probe.CommandID == command.ID {
				session.State.Probe.CommandID = id
			}
			command.ID = id
			sent = append(sent, syncMLSentCommand{ID: id, Kind: command.Kind})
			assign(command.Commands)
		}
	}
	assign(response.Commands)
	return sent
}

func syncMLResponseCommandID(session *syncMLSession, messageID string, index int) string {
	return session.ID + "-" + messageID + "-" + strconv.Itoa(index+1)
}

func processSyncMLServerAuthentication(record *syncMLDeviceRecord, session *syncMLSession, request *SyncMLMessage) (bool, error) {
	state := &session.State
	var status *SyncMLCommand
	for n := range request.Commands {
		command := &request.Commands[n]
		if command.Kind != "Status" || command.CommandName != "SyncHdr" {
			continue
		}
		if status != nil || command.MessageRef != strconv.Itoa(session.LastMessage) || (command.CommandRef != "0" && command.CommandRef != "") {
			return false, ErrSyncMLSession
		}
		status = command
	}
	if status == nil || status.Data == nil {
		return false, ErrSyncMLSession
	}
	switch status.Data.Text {
	case "212":
		if !state.LastServerCredential && !state.ServerAuthenticated {
			return false, ErrSyncMLSession
		}
		state.ServerAuthenticated, state.ServerVerified = true, true
		if status.Challenge != nil {
			record.Nonces.ServerNonce = status.Challenge.NextNonce
		}
	case "200":
		state.ServerVerified = true
		if status.Challenge != nil {
			if !state.LastServerCredential {
				return false, ErrSyncMLSession
			}
			state.ServerNonce, record.Nonces.ServerNonce = status.Challenge.NextNonce, status.Challenge.NextNonce
		}
	case "401", "407":
		if status.Challenge == nil || !state.LastServerCredential || state.ServerAuthenticated {
			return false, ErrSyncMLSession
		}
		for _, command := range request.Commands {
			if command.Kind != "Status" || command.Data == nil || (command.Data.Text != "401" && command.Data.Text != "407") {
				return false, ErrSyncMLSession
			}
		}
		if state.ServerChallenges >= 1 {
			session.Phase = "failed"
			return false, nil
		}
		state.ServerChallenges++
		state.ServerVerified = false
		session.Phase = "authenticating"
		state.ServerNonce, record.Nonces.ServerNonce = status.Challenge.NextNonce, status.Challenge.NextNonce
		state.Probe = nil
		state.IncomingChunk = nil
		return true, nil
	default:
		session.Phase = "failed"
	}
	return false, nil
}

func syncMLProbeFailed(probe *syncMLIdentityProbe) bool {
	code, err := strconv.Atoi(probe.Status)
	return err == nil && code >= 400
}

func processSyncMLClientCommands(session *syncMLSession, request, response *SyncMLMessage, serverRetry bool) error {
	state := &session.State
	seenStatuses := map[string]bool{}
	seenResults := map[string]bool{}
	seenItems := map[string]bool{}
	previousChunk := state.IncomingChunk
	continuedChunk := false
	for _, command := range request.Commands {
		if syncMLTerminal(session.Phase) {
			break
		}
		if state.IncomingChunk != nil && command.Kind != "Status" && command.Kind != "Alert" && command.Kind != state.IncomingChunk.Kind {
			failSyncMLChunk(session, request, response, command, "1225")
			break
		}
		switch command.Kind {
		case "Status":
			if command.CommandName == "SyncHdr" {
				continue
			}
			key := command.MessageRef + "\x00" + command.CommandRef
			if seenStatuses[key] || command.Data == nil {
				return ErrSyncMLSession
			}
			seenStatuses[key] = true
			known := false
			if command.MessageRef == strconv.Itoa(session.LastMessage) {
				for _, sent := range state.LastResponse {
					if sent.ID == command.CommandRef && sent.Kind == command.CommandName {
						known = true
					}
				}
			}
			if probe := state.Probe; !serverRetry && probe != nil && command.MessageRef == probe.MessageID && command.CommandRef == probe.CommandID && command.CommandName == "Get" {
				known = true
				if probe.Status != "" && probe.Status != command.Data.Text {
					return ErrSyncMLSession
				}
				probe.Status = command.Data.Text
			}
			if !known {
				return ErrSyncMLSession
			}
		case "Results":
			probe := state.Probe
			key := command.MessageRef + "\x00" + command.CommandRef
			if serverRetry || probe == nil || seenResults[key] || command.MessageRef != probe.MessageID || command.CommandRef != probe.CommandID || len(command.Items) != 1 {
				return ErrSyncMLSession
			}
			seenResults[key] = true
			item := command.Items[0]
			if item.Source == nil || item.Source.URI != "./DevInfo/DevId" || item.Target != nil || item.Data == nil || item.Data.XML != "" || item.Data.OriginalError != "" || (probe.HasResult && !probe.MoreData) {
				return ErrSyncMLSession
			}
			assembled, code, err := receiveSyncMLText(session, request, response, command, item, probe.Data)
			if err != nil {
				return err
			}
			if session.Phase == "failed" {
				break
			}
			continuedChunk = true
			probe.Data = assembled
			probe.HasResult, probe.MoreData = true, item.MoreData
			if code == "213" {
				syncMLStatus(response, request.Header.MessageID, command.ID, command.Kind, code)
			}
			if !probe.MoreData && probe.Data != state.DeviceInfo["./DevInfo/DevId"] {
				return ErrSyncMLSession
			}
		case "Replace":
			code := "200"
			if state.Probe != nil || !syncMLTextMetadata(command.Meta) {
				code = "405"
			}
			for _, item := range command.Items {
				if item.Source == nil || !syncMLDeviceInfoURI(item.Source.URI) || item.Target != nil {
					code = "404"
					break
				}
				if item.Data == nil || item.Data.XML != "" || item.Data.OriginalError != "" || !syncMLTextMetadata(item.Meta) || len(item.Data.Text) > maxSyncMLDeviceInfoBytes {
					code = "415"
					break
				}
			}
			if code == "200" {
				for _, item := range command.Items {
					uri := item.Source.URI
					if state.IncomingChunk != nil && state.IncomingChunk.URI != uri {
						failSyncMLChunk(session, request, response, command, "1225")
						break
					}
					if seenItems[uri] {
						return ErrSyncMLSession
					}
					seenItems[uri] = true
					if _, exists := state.DeviceInfo[uri]; exists && !state.IncompleteInfo[uri] {
						return ErrSyncMLSession
					}
					assembled, receivedCode, err := receiveSyncMLText(session, request, response, command, item, state.DeviceInfo[uri])
					if err != nil {
						return err
					}
					if session.Phase == "failed" {
						break
					}
					continuedChunk = true
					code = receivedCode
					state.DeviceInfo[uri] = assembled
					state.IncompleteInfo[uri] = item.MoreData
				}
			}
			if session.Phase == "failed" {
				break
			}
			syncMLStatus(response, request.Header.MessageID, command.ID, command.Kind, code)
		case "Alert":
			code := "200"
			switch command.Data.Text {
			case "1200", "1201", "1222":
			case "1223":
				session.Phase = "aborted"
			case "1224":
				if len(command.Items) != 1 || command.Items[0].Meta == nil || command.Items[0].Meta.Type != "com.microsoft/MDM/LoginStatus" || command.Items[0].Data == nil || command.Items[0].Data.XML != "" || command.Items[0].MoreData {
					code = "406"
					break
				}
				value := strings.ToLower(command.Items[0].Data.Text)
				if value != "user" && value != "others" && value != "none" {
					code = "406"
				} else {
					state.LoginStatus = value
				}
			default:
				code = "406"
			}
			syncMLStatus(response, request.Header.MessageID, command.ID, command.Kind, code)
		default:
			syncMLRejectCommands(response, request.Header.MessageID, []SyncMLCommand{command}, "405")
		}
	}
	if !syncMLTerminal(session.Phase) && previousChunk != nil && !continuedChunk {
		failSyncMLChunk(session, request, response, SyncMLCommand{}, "1225")
	}
	if !syncMLTerminal(session.Phase) && request.Final && state.IncomingChunk != nil {
		return ErrSyncMLSession
	}
	if state.Probe != nil && state.Probe.HasResult && syncMLProbeFailed(state.Probe) {
		return ErrSyncMLSession
	}
	return nil
}

func syncMLTextMetadata(meta *SyncMLMeta) bool {
	return meta == nil || (meta.Format == "" || meta.Format == "chr") && (meta.Type == "" || meta.Type == "text/plain") && (meta.Size == nil || *meta.Size <= maxSyncMLDeviceInfoBytes)
}
