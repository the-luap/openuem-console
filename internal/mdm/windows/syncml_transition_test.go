package windows

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func syncMLTestSecrets() *syncMLBootstrapSecrets {
	value := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	return &syncMLBootstrapSecrets{ClientSecret: value(1), ServerSecret: value(2), ClientNonce: value(3), ServerNonce: value(4)}
}

func syncMLTestTransition() (ManagementDeviceIdentity, *syncMLDeviceRecord, *syncMLSession) {
	i := ManagementDeviceIdentity{DeviceID: managementTestDeviceID, CertificateID: "22222222-2222-4222-8222-222222222222", AuthorityID: "33333333-3333-4333-8333-333333333333", Scope: credentialTestScope}
	secrets := syncMLTestSecrets()
	now := time.Now().UTC()
	record := &syncMLDeviceRecord{Revision: 1, CreatedAt: now, Nonces: syncMLDeviceNonces{Version: 1, ClientNonce: secrets.ClientNonce, ServerNonce: secrets.ServerNonce}}
	session := &syncMLSession{ID: "44444444-4444-4444-8444-444444444444", WireID: "1", Phase: "authenticating", Revision: 1, CreatedAt: now, ExpiresAt: now.Add(syncMLSessionLifetime), State: syncMLSessionState{Version: 1, SourceURI: "urn:uuid:synthetic-windows-client", ClientNonce: secrets.ClientNonce, ServerNonce: secrets.ServerNonce, MaximumResponseBytes: 5000, DeviceInfo: map[string]string{}, IncompleteInfo: map[string]bool{}}}
	return i, record, session
}

func syncMLTestInitial(identity ManagementDeviceIdentity, options EnrollmentOptions, secrets *syncMLBootstrapSecrets) *SyncMLMessage {
	digest, _ := syncMLDigest(identity.DeviceID, secrets.ClientSecret, secrets.ClientNonce)
	maximum := uint64(5000)
	message := &SyncMLMessage{Header: SyncMLHeader{SessionID: "1", MessageID: "1", Source: SyncMLLocation{URI: "urn:uuid:synthetic-windows-client", Name: identity.DeviceID}, Target: SyncMLLocation{URI: options.ManagementURL}, Credential: &SyncMLCredential{Digest: digest}, Meta: &SyncMLMeta{MaxMessageSize: &maximum}}, Final: true}
	message.Commands = append(message.Commands, SyncMLCommand{Kind: "Alert", ID: "1", Data: &SyncMLData{Text: "1224"}, Items: []SyncMLItem{{Meta: &SyncMLMeta{Type: "com.microsoft/MDM/LoginStatus"}, Data: &SyncMLData{Text: "user"}}}})
	info := SyncMLCommand{Kind: "Replace", ID: "2"}
	for n, uri := range syncMLRequiredDeviceInfo {
		info.Items = append(info.Items, SyncMLItem{Source: &SyncMLLocation{URI: uri}, Meta: &SyncMLMeta{Format: "chr"}, Data: &SyncMLData{Text: []string{"synthetic-device-ä<&>", "Synthetic manufacturer", "Synthetic model", "1.2", "en-US"}[n]}})
	}
	message.Commands = append(message.Commands, info)
	return message
}

func syncMLTestWire(t testing.TB, message *SyncMLMessage) []byte {
	t.Helper()
	data, err := EncodeSyncML(message)
	if err != nil {
		t.Fatal("invalid synthetic SyncML fixture", err)
	}
	return data
}

func syncMLTestParsed(t testing.TB, data []byte) *SyncMLMessage {
	t.Helper()
	message, err := ParseSyncML(data)
	if err != nil {
		t.Fatal("invalid SyncML response", err)
	}
	return message
}

func syncMLTestReply(response *SyncMLMessage) *SyncMLMessage {
	n, _ := strconv.Atoi(response.Header.MessageID)
	request := &SyncMLMessage{Header: SyncMLHeader{SessionID: response.Header.SessionID, MessageID: strconv.Itoa(n + 1), Source: response.Header.Target, Target: response.Header.Source}, Final: true}
	syncMLStatus(request, response.Header.MessageID, "0", "SyncHdr", "212")
	for _, command := range response.Commands {
		if command.Kind == "Get" {
			syncMLStatus(request, response.Header.MessageID, command.ID, "Get", "200")
			request.Commands = append(request.Commands, SyncMLCommand{Kind: "Results", ID: strconv.Itoa(len(request.Commands) + 1), MessageRef: response.Header.MessageID, CommandRef: command.ID, Items: []SyncMLItem{{Source: &SyncMLLocation{URI: "./DevInfo/DevId"}, Data: &SyncMLData{Text: "synthetic-device-ä<&>"}}}})
		}
	}
	return request
}

func syncMLTestAdvance(t testing.TB, identity ManagementDeviceIdentity, record *syncMLDeviceRecord, session *syncMLSession, request *SyncMLMessage) (*SyncMLMessage, []string) {
	t.Helper()
	request = syncMLTestParsed(t, syncMLTestWire(t, request))
	response, events, err := advanceSyncMLSession(identity, enrollmentTestOptions(), record, session, request, syncMLTestSecrets())
	if err != nil {
		t.Fatal("session transition failed", err)
	}
	if session.validate() != nil {
		t.Fatal("transition produced invalid protected state")
	}
	return syncMLTestParsed(t, syncMLTestWire(t, response)), events
}

func TestSyncMLSessionMutualAuthenticationAndReadOnlyProbe(t *testing.T) {
	identity, record, session := syncMLTestTransition()
	first := syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets())
	response, events := syncMLTestAdvance(t, identity, record, session, first)
	if len(events) != 0 || session.Phase != "authenticating" || session.State.ServerVerified || response.Commands[0].Data.Text != "212" || response.Commands[0].Challenge == nil || response.Commands[len(response.Commands)-1].Kind != "Get" {
		t.Fatal("initial response claimed mutual authentication or missed read-only probe")
	}
	if record.Nonces.ClientNonce == syncMLTestSecrets().ClientNonce || session.State.ClientNonce != syncMLTestSecrets().ClientNonce || verifySyncMLDigest(enrollmentTestOptions().ProviderID, syncMLTestSecrets().ServerSecret, record.Nonces.ServerNonce, response.Header.Credential.Digest) != nil {
		t.Fatal("initial digest or next-session nonce is incorrect")
	}
	request := syncMLTestReply(response)
	nextServerNonce, _ := newSyncMLNonce()
	request.Commands[0].Challenge = syncMLChallenge(nextServerNonce)
	final, events := syncMLTestAdvance(t, identity, record, session, request)
	if session.Phase != "completed" || !session.State.ServerAuthenticated || final.Header.Credential != nil || !slices.Equal(events, []string{"session.authenticated", "session.completed"}) || len(final.Commands) != 1 || !final.Final || session.State.Probe.Data != first.Commands[1].Items[0].Data.Text {
		t.Fatal("successful probe did not finish an authenticated exchange")
	}
	if record.Nonces.ServerNonce != nextServerNonce || session.State.ServerNonce != syncMLTestSecrets().ServerNonce {
		t.Fatal("212 nonce was applied to the current session")
	}
}

func TestSyncMLSessionClientChallengeRetryAndFailure(t *testing.T) {
	for _, credentials := range []bool{false, true} {
		identity, record, session := syncMLTestTransition()
		first := syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets())
		if !credentials {
			first.Header.Credential = nil
		} else {
			first.Header.Credential.Digest = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}
		response, events := syncMLTestAdvance(t, identity, record, session, first)
		if !slices.Equal(events, []string{"session.challenged"}) || session.State.ClientAuthenticated || len(session.State.DeviceInfo) != 0 || record.Nonces.ClientNonce == syncMLTestSecrets().ClientNonce {
			t.Fatal("challenge processed unauthenticated device information")
		}
		for _, command := range response.Commands {
			if command.Kind != "Status" || command.Data.Text != map[bool]string{true: "401", false: "407"}[credentials] {
				t.Fatal("authentication failure emitted an operation")
			}
		}
		retry := syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets())
		retry.Header.MessageID = "2"
		retry.Header.Credential.Digest, _ = syncMLDigest(identity.DeviceID, syncMLTestSecrets().ClientSecret, record.Nonces.ClientNonce)
		syncMLStatus(retry, "1", "0", "SyncHdr", "212")
		accepted, _ := syncMLTestAdvance(t, identity, record, session, retry)
		if session.Phase != "active" || session.State.Probe == nil || accepted.Header.Credential != nil {
			t.Fatal("same-session authentication retry was not accepted")
		}
		bad := syncMLTestReply(accepted)
		bad.Header.Credential = first.Header.Credential
		if bad.Header.Credential == nil {
			bad.Header.Credential = &SyncMLCredential{Digest: base64.StdEncoding.EncodeToString(make([]byte, 16))}
		}
		_, events = syncMLTestAdvance(t, identity, record, session, bad)
		if session.Phase != "failed" || !slices.Equal(events, []string{"session.failed"}) {
			t.Fatal("repeated invalid client proof did not stop the session")
		}
	}
}

func TestSyncMLSessionServerChallengeAndPerMessageNonce(t *testing.T) {
	identity, record, session := syncMLTestTransition()
	response, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
	request := syncMLTestReply(response)
	request.Commands = request.Commands[:2]
	for n := range request.Commands {
		request.Commands[n].Data.Text = "401"
	}
	nonce, _ := newSyncMLNonce()
	request.Commands[0].Challenge = syncMLChallenge(nonce)
	retry, _ := syncMLTestAdvance(t, identity, record, session, request)
	if session.State.ServerVerified || session.State.ServerChallenges != 1 || session.State.Probe.MessageID != "2" || verifySyncMLDigest(enrollmentTestOptions().ProviderID, syncMLTestSecrets().ServerSecret, nonce, retry.Header.Credential.Digest) != nil {
		t.Fatal("server challenge did not rotate proof and reissue rejected probe")
	}
	request = syncMLTestReply(retry)
	request.Commands[0].Data.Text = "200"
	newNonce, _ := newSyncMLNonce()
	request.Commands[0].Challenge = syncMLChallenge(newNonce)
	final, _ := syncMLTestAdvance(t, identity, record, session, request)
	if session.Phase != "completed" || session.State.ServerAuthenticated || !session.State.ServerVerified || final.Header.Credential == nil || verifySyncMLDigest(enrollmentTestOptions().ProviderID, syncMLTestSecrets().ServerSecret, newNonce, final.Header.Credential.Digest) != nil {
		t.Fatal("200 did not require the new next-message credential")
	}
}

func TestSyncMLSessionRejectsUncorrelatedOrConflictingResults(t *testing.T) {
	for name, mutate := range map[string]func(*SyncMLMessage){
		"message gap":             func(m *SyncMLMessage) { m.Header.MessageID = "3" },
		"wire session":            func(m *SyncMLMessage) { m.Header.SessionID = "other" },
		"source URI":              func(m *SyncMLMessage) { m.Header.Source.URI = "urn:other" },
		"target URI":              func(m *SyncMLMessage) { m.Header.Target.URI = "https://other.example.test/management" },
		"redirect":                func(m *SyncMLMessage) { m.Header.ResponseURI = "https://other.example.test/collect" },
		"header reference":        func(m *SyncMLMessage) { m.Commands[0].MessageRef = "0" },
		"missing header status":   func(m *SyncMLMessage) { m.Commands = m.Commands[1:] },
		"duplicate header status": func(m *SyncMLMessage) { c := m.Commands[0]; c.ID = "4"; m.Commands = append(m.Commands, c) },
		"status reference":        func(m *SyncMLMessage) { m.Commands[1].CommandRef = "unknown" },
		"result reference":        func(m *SyncMLMessage) { m.Commands[2].MessageRef = "0" },
		"result URI":              func(m *SyncMLMessage) { m.Commands[2].Items[0].Source.URI = "./DevInfo/Man" },
		"result mismatch":         func(m *SyncMLMessage) { m.Commands[2].Items[0].Data.Text = "other device" },
		"duplicate status":        func(m *SyncMLMessage) { c := m.Commands[1]; c.ID = "4"; m.Commands = append(m.Commands, c) },
		"duplicate result":        func(m *SyncMLMessage) { c := m.Commands[2]; c.ID = "4"; m.Commands = append(m.Commands, c) },
		"oversized result": func(m *SyncMLMessage) {
			m.Commands[2].Items[0].Data.Text = strings.Repeat("x", maxSyncMLDeviceInfoBytes+1)
		},
		"original error result": func(m *SyncMLMessage) { m.Commands[2].Items[0].Data.OriginalError = "0x80070005" },
	} {
		t.Run(name, func(t *testing.T) {
			identity, record, session := syncMLTestTransition()
			response, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
			request := syncMLTestReply(response)
			mutate(request)
			request = syncMLTestParsed(t, syncMLTestWire(t, request))
			if response, _, err := advanceSyncMLSession(identity, enrollmentTestOptions(), record, session, request, syncMLTestSecrets()); err == nil || response != nil {
				t.Fatal("inconsistent exchange returned a response")
			}
		})
	}
}

func TestSyncMLSessionIncompleteProbeAndDeviceInformation(t *testing.T) {
	identity, record, session := syncMLTestTransition()
	initial := syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets())
	initial.Final = false
	total := uint64(len(initial.Commands[1].Items[0].Data.Text))
	initial.Commands[1].Items[0].Data.Text = "synthetic-"
	initial.Commands[1].Items[0].MoreData = true
	initial.Commands[1].Items[0].Meta.Size = &total
	// The incomplete object must be the final item; chunks are contiguous.
	item := initial.Commands[1].Items[0]
	initial.Commands[1].Items = append(initial.Commands[1].Items[1:], item)
	first, _ := syncMLTestAdvance(t, identity, record, session, initial)
	if session.State.Probe != nil || first.Final || first.Commands[len(first.Commands)-1].Data.Text != "1222" || first.Commands[len(first.Commands)-2].Data.Text != "213" {
		t.Fatal("partial DevInfo dispatched a probe")
	}
	second := syncMLTestReply(first)
	second.Commands = append(second.Commands, SyncMLCommand{Kind: "Replace", ID: "2", Items: []SyncMLItem{{Source: &SyncMLLocation{URI: "./DevInfo/DevId"}, Data: &SyncMLData{Text: "device-ä<&>"}}}})
	probeResponse, _ := syncMLTestAdvance(t, identity, record, session, second)
	partial := syncMLTestReply(probeResponse)
	partial.Final = false
	partial.Commands[2].Items[0].Data.Text = "synthetic-"
	partial.Commands[2].Items[0].MoreData = true
	partial.Commands[2].Items[0].Meta = &SyncMLMeta{Size: &total}
	third, _ := syncMLTestAdvance(t, identity, record, session, partial)
	if session.Phase != "active" || !session.State.Probe.MoreData || third.Final || third.Commands[1].Data.Text != "213" {
		t.Fatal("partial Results completed the probe")
	}
	last := syncMLTestReply(third)
	last.Commands = append(last.Commands, SyncMLCommand{Kind: "Results", ID: "2", MessageRef: session.State.Probe.MessageID, CommandRef: session.State.Probe.CommandID, Items: []SyncMLItem{{Source: &SyncMLLocation{URI: "./DevInfo/DevId"}, Data: &SyncMLData{Text: "device-ä<&>"}}}})
	_, events := syncMLTestAdvance(t, identity, record, session, last)
	if session.Phase != "completed" || !slices.Equal(events, []string{"session.completed"}) {
		t.Fatal("completed chunked probe did not close the exchange")
	}
}

func TestSyncMLSessionBoundsAndDiagnosticPrivacy(t *testing.T) {
	identity, record, session := syncMLTestTransition()
	first, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
	for _, value := range []any{record, session, &session.State, &record.Nonces, session.State.Probe} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, record.Nonces.ClientNonce) || strings.Contains(rendered, session.State.SourceURI) || strings.Contains(rendered, "synthetic-device") {
				t.Fatal("session diagnostic leaked protected content")
			}
		}
	}
	request := syncMLTestReply(first)
	request.Commands = request.Commands[:1]
	session.LastMessage = 63
	request.Header.MessageID = "64"
	request.Commands[0].MessageRef = "63"
	response, events := syncMLTestAdvance(t, identity, record, session, request)
	if session.Phase != "failed" || response.Commands[len(response.Commands)-1].Data.Text != "1223" || !slices.Contains(events, "session.failed") {
		t.Fatal("message budget did not stop an unfinished session")
	}
}

func TestSyncMLSessionChunkSizesAndContiguousObjects(t *testing.T) {
	for name, mutate := range map[string]func(*SyncMLMessage){
		"size mismatch": func(m *SyncMLMessage) { m.Commands[1].Items[0].Data.Text = "wrong" },
		"different object": func(m *SyncMLMessage) {
			m.Commands[1] = SyncMLCommand{Kind: "Replace", ID: "2", Items: []SyncMLItem{{Source: &SyncMLLocation{URI: "./DevInfo/Man"}, Data: &SyncMLData{Text: "other"}}}}
		},
		"missing continuation": func(m *SyncMLMessage) { m.Commands = m.Commands[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			identity, record, session := syncMLTestTransition()
			first, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
			partial := syncMLTestReply(first)
			partial.Final = false
			total := uint64(len(partial.Commands[2].Items[0].Data.Text))
			partial.Commands[2].Items[0].Meta = &SyncMLMeta{Size: &total}
			partial.Commands[2].Items[0].Data.Text = "synthetic-"
			partial.Commands[2].Items[0].MoreData = true
			response, _ := syncMLTestAdvance(t, identity, record, session, partial)
			last := syncMLTestReply(response)
			last.Commands = append(last.Commands, SyncMLCommand{Kind: "Results", ID: "2", MessageRef: session.State.Probe.MessageID, CommandRef: session.State.Probe.CommandID, Items: []SyncMLItem{{Source: &SyncMLLocation{URI: "./DevInfo/DevId"}, Data: &SyncMLData{Text: "device-ä<&>"}}}})
			mutate(last)
			failed, events := syncMLTestAdvance(t, identity, record, session, last)
			if session.Phase != "failed" || !slices.Equal(events, []string{"session.failed"}) || session.State.Probe.Data != "synthetic-" {
				t.Fatal("invalid chunk committed an object or stayed active")
			}
			want := "1225"
			if name == "size mismatch" {
				want = "424"
			}
			if failed.Commands[1].Data.Text != want {
				t.Fatal("chunk failure did not report the appropriate status or alert")
			}
		})
	}
	for _, missingSize := range []bool{false, true} {
		identity, record, session := syncMLTestTransition()
		first, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
		partial := syncMLTestReply(first)
		partial.Commands[2].Items[0].MoreData = true
		total := uint64(100)
		partial.Commands[2].Items[0].Meta = &SyncMLMeta{Size: &total}
		if missingSize {
			partial.Final = false
			partial.Commands[2].Items[0].Meta = nil
		}
		if response, _, err := advanceSyncMLSession(identity, enrollmentTestOptions(), record, session, partial, syncMLTestSecrets()); err == nil || response != nil {
			t.Fatal("incomplete object accepted without size or with premature Final")
		}
	}
}

func TestSyncMLSessionAbortFailedProbeAndRepeatedServerChallenge(t *testing.T) {
	for _, outcome := range []string{"abort", "failed probe", "repeated server challenge"} {
		t.Run(outcome, func(t *testing.T) {
			identity, record, session := syncMLTestTransition()
			first, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
			request := syncMLTestReply(first)
			switch outcome {
			case "abort":
				request.Commands = request.Commands[:1]
				request.Commands = append(request.Commands, SyncMLCommand{Kind: "Alert", ID: "2", Data: &SyncMLData{Text: "1223"}})
			case "failed probe":
				request.Commands = request.Commands[:2]
				request.Commands[1].Data.Text = "404"
			case "repeated server challenge":
				for n := 0; n < 2; n++ {
					request.Commands = request.Commands[:2]
					for index := range request.Commands {
						request.Commands[index].Data.Text = "401"
					}
					nonce, _ := newSyncMLNonce()
					request.Commands[0].Challenge = syncMLChallenge(nonce)
					response, _ := syncMLTestAdvance(t, identity, record, session, request)
					if n == 0 {
						request = syncMLTestReply(response)
					}
				}
				if session.Phase != "failed" {
					t.Fatal("repeated server challenge remained active")
				}
				return
			}
			_, events := syncMLTestAdvance(t, identity, record, session, request)
			want := "aborted"
			if outcome == "failed probe" {
				want = "completed"
				if session.State.Probe.HasResult {
					t.Fatal("failed Get recorded a successful result")
				}
			}
			if session.Phase != want || !slices.Contains(events, "session."+want) {
				t.Fatal("terminal exchange was not recorded")
			}
		})
	}
}

func FuzzSyncMLSessionTransition(f *testing.F) {
	identity, record, session := syncMLTestTransition()
	first := syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets())
	f.Add(syncMLTestWire(f, first), false)
	response, _ := syncMLTestAdvance(f, identity, record, session, first)
	f.Add(syncMLTestWire(f, syncMLTestReply(response)), true)
	f.Fuzz(func(t *testing.T, data []byte, continuation bool) {
		request, err := ParseSyncML(data)
		if err != nil {
			return
		}
		identity, record, session := syncMLTestTransition()
		if continuation {
			syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
		}
		response, _, err := advanceSyncMLSession(identity, enrollmentTestOptions(), record, session, request, syncMLTestSecrets())
		if err != nil {
			if response != nil {
				t.Fatal("failed transition leaked response")
			}
			return
		}
		if session.validate() != nil {
			t.Fatal("accepted transition produced invalid state")
		}
		if encoded, err := EncodeSyncML(response); err == nil {
			syncMLTestParsed(t, encoded)
		}
	})
}
