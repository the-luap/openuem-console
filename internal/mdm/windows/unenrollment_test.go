package windows

import (
	"encoding/base64"
	"testing"
)

func TestWindowsUnenrollmentGrammarRequiresOneCompleteFirstPackage(t *testing.T) {
	identity, record, _ := syncMLTestTransition()
	secrets := syncMLTestSecrets()
	fixture := syncMLStoreFixture{identity: identity, options: enrollmentTestOptions(), secrets: secrets}
	fresh := func() *SyncMLMessage { return unenrollmentTestMessage(t, fixture, secrets.ClientNonce) }
	for name, change := range map[string]func(*SyncMLMessage){
		"later message":          func(m *SyncMLMessage) { m.Header.MessageID = "2" },
		"unfinished package":     func(m *SyncMLMessage) { m.Final = false },
		"redirect":               func(m *SyncMLMessage) { m.Header.ResponseURI = "https://other.example.test/management" },
		"duplicate notification": func(m *SyncMLMessage) { c := m.Commands[2]; c.ID = "4"; m.Commands = append(m.Commands, c) },
		"nested notification": func(m *SyncMLMessage) {
			m.Commands = []SyncMLCommand{{Kind: "Sequence", ID: "4", Commands: m.Commands}}
		},
		"wrong command":     func(m *SyncMLMessage) { m.Commands[2].Kind = "Replace" },
		"wrong alert":       func(m *SyncMLMessage) { m.Commands[2].Data.Text = "1224" },
		"unsupported value": func(m *SyncMLMessage) { m.Commands[2].Items[0].Data.Text = "0" },
		"ambiguous value":   func(m *SyncMLMessage) { m.Commands[2].Items[0].Data.Text = "01" },
		"whitespace value":  func(m *SyncMLMessage) { m.Commands[2].Items[0].Data.Text = " 1 " },
		"markup value":      func(m *SyncMLMessage) { m.Commands[2].Items[0].Data = &SyncMLData{XML: "<value>1</value>"} },
		"error annotation":  func(m *SyncMLMessage) { m.Commands[2].Items[0].Data.OriginalError = "1" },
		"wrong format":      func(m *SyncMLMessage) { m.Commands[2].Items[0].Meta.Format = "chr" },
		"unexpected nonce":  func(m *SyncMLMessage) { m.Commands[2].Items[0].Meta.NextNonce = secrets.ClientNonce },
		"extra item": func(m *SyncMLMessage) {
			m.Commands[2].Items = append(m.Commands[2].Items, SyncMLItem{Data: &SyncMLData{Text: "extra"}})
		},
		"source hint": func(m *SyncMLMessage) { m.Commands[2].Items[0].Source = &SyncMLLocation{URI: "foreign-device"} },
		"chunk":       func(m *SyncMLMessage) { m.Commands[2].Items[0].MoreData = true },
		"mixed device command": func(m *SyncMLMessage) {
			m.Commands = append(m.Commands, SyncMLCommand{Kind: "Exec", ID: "4", Items: []SyncMLItem{{Target: &SyncMLLocation{URI: "./Device/Vendor/MSFT/Test/Run"}}}})
		},
		"old command status": func(m *SyncMLMessage) {
			m.Commands = append(m.Commands, SyncMLCommand{Kind: "Status", ID: "4", MessageRef: "2", CommandRef: "old", CommandName: "Exec", Data: &SyncMLData{Text: "200"}})
		},
		"unrelated inventory": func(m *SyncMLMessage) { m.Commands[1].Items[0].Source.URI = "./Device/Vendor/MSFT/Test/Value" },
	} {
		t.Run(name, func(t *testing.T) {
			m := fresh()
			change(m)
			if got, err := syncMLUnenrollmentAlert(m); err == nil || got != nil {
				t.Fatal("malformed terminal notification admitted")
			}
		})
	}
	for name, change := range map[string]func(*SyncMLMessage){
		"no credential": func(m *SyncMLMessage) { m.Header.Credential = nil },
		"wrong digest": func(m *SyncMLMessage) {
			m.Header.Credential.Digest = base64.StdEncoding.EncodeToString(make([]byte, 16))
		},
		"foreign source name": func(m *SyncMLMessage) { m.Header.Source.Name = "another-device" },
		"wrong endpoint":      func(m *SyncMLMessage) { m.Header.Target.URI = "https://other.example.test/management" },
		"wrong provider":      func(m *SyncMLMessage) { m.Header.Target.Name = "OtherProvider" },
		"response limit":      func(m *SyncMLMessage) { n := uint64(1); m.Header.Meta = &SyncMLMeta{MaxMessageSize: &n} },
	} {
		t.Run(name, func(t *testing.T) {
			m := fresh()
			change(m)
			alert, err := syncMLUnenrollmentAlert(m)
			if err != nil || alert == nil {
				t.Fatal(err)
			}
			if response, err := unenrollmentResponse(identity, fixture.options, m, alert, secrets, record.Nonces); err == nil || response != nil {
				t.Fatal("unauthorized notification response produced")
			}
		})
	}
	m := fresh()
	m.Commands = m.Commands[2:]
	alert, err := syncMLUnenrollmentAlert(m)
	if err != nil || alert == nil {
		t.Fatal(err)
	}
	if _, err := unenrollmentResponse(identity, fixture.options, m, alert, secrets, record.Nonces); err != nil {
		t.Fatal("notification incorrectly required an inventory/probe exchange", err)
	}
	m = fresh()
	m.Commands[2].Items[0].Meta.Type = "com.example/unrelated"
	if alert, err := syncMLUnenrollmentAlert(m); err != nil || alert != nil {
		t.Fatal("unrelated generic alert became disconnection")
	}
}

func FuzzWindowsUnenrollment(f *testing.F) {
	identity, record, _ := syncMLTestTransition()
	secrets := syncMLTestSecrets()
	request := syncMLTestInitial(identity, enrollmentTestOptions(), secrets)
	request.Commands = append(request.Commands, SyncMLCommand{Kind: "Alert", ID: "3", Data: &SyncMLData{Text: "1226"}, Items: []SyncMLItem{{Meta: &SyncMLMeta{Type: windowsUnenrollmentAlertType, Format: "int"}, Data: &SyncMLData{Text: "1"}}}})
	f.Add(syncMLTestWire(f, request))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxSyncMLBytes {
			return
		}
		request, err := ParseSyncML(data)
		if err != nil {
			return
		}
		alert, err := syncMLUnenrollmentAlert(request)
		if err != nil || alert == nil {
			return
		}
		response, err := unenrollmentResponse(identity, enrollmentTestOptions(), request, alert, secrets, record.Nonces)
		if err != nil {
			return
		}
		parsed, err := ParseSyncML(response)
		if err != nil || !parsed.Final || parsed.Header.MessageID != "1" {
			t.Fatal("accepted notification produced invalid response", err)
		}
		for _, c := range parsed.Commands {
			if c.Kind != "Status" {
				t.Fatal("notification response dispatched device work")
			}
		}
	})
}
