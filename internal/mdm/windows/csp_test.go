package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const cspTestPolicyURI = "./Device/Vendor/MSFT/Policy/Config/Update/ConfigureDeadlineForQualityUpdates"

func cspTestPolicy() CSPCommandSpec {
	return CSPCommandSpec{Kind: "Replace", URI: cspTestPolicyURI, Format: "int", Data: &SyncMLData{Text: "7"}}
}

func TestCSPCompilerCanonicalTargetsTypesAndGroups(t *testing.T) {
	valid := []CSPCommandSpec{
		cspTestPolicy(),
		{Kind: "Get", URI: "./DevDetail/SwV"},
		{Kind: "Delete", URI: cspTestPolicyURI},
		{Kind: "Add", URI: "./Device/Vendor/MSFT/Policy/Config/TestNode", Format: "node"},
		{Kind: "Exec", URI: "./Device/Vendor/MSFT/RemoteLock/Lock"},
		{Kind: "Replace", URI: "./User/Vendor/MSFT/WiFi/Profile/Synthetic%20%C3%A4/WlanXml", Format: "chr", Data: &SyncMLData{Text: "<synthetic>private & configuration</synthetic>"}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "b64", Data: &SyncMLData{Text: "AAECAw=="}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "bool", Data: &SyncMLData{Text: "true"}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "xml", MIME: "application/xml", Data: &SyncMLData{XML: `<x xmlns="urn:synthetic:csp">private</x>`}},
		{Kind: "Sequence", Commands: []CSPCommandSpec{{Kind: "Get", URI: "./DevInfo/Man"}, {Kind: "Atomic", Commands: []CSPCommandSpec{cspTestPolicy()}}}},
	}
	for _, spec := range valid {
		encoded, user, err := encodeCSPRequest(spec)
		if err != nil {
			t.Fatal("valid custom CSP command rejected", err)
		}
		command, decodedUser, err := decodeCSPRequest(encoded)
		if err != nil || decodedUser != user || command.Kind != spec.Kind {
			t.Fatal("protected CSP representation changed request", err)
		}
		preview, err := PreviewCSPCommand(spec)
		if err != nil || preview.UserTarget != user || preview.EncodedBytes != len(encoded) || preview.Command.Kind != command.Kind {
			t.Fatal("CSP preview differs from admitted compilation", err)
		}
		if value, err := json.Marshal(preview); err != nil || string(value) != "{}" || strings.Contains(fmt.Sprintf("%+v", preview), spec.URI) && spec.URI != "" {
			t.Fatal("CSP preview exposed protected intent")
		}
		if user != strings.HasPrefix(spec.URI, "./User/") {
			t.Fatal("incorrect user-target classification")
		}
		ordinary, err := json.Marshal(spec)
		if err != nil || string(ordinary) != "{}" {
			t.Fatal("ordinary JSON exposed CSP request data")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if value := fmt.Sprintf(format, spec); strings.Contains(value, "private") || strings.Contains(value, "Vendor/MSFT") {
				t.Fatal("CSP diagnostic exposed a payload")
			}
		}
	}
	for _, uri := range []string{"https://outside.example.test/config", "/Device/Vendor/MSFT/Policy", "./Vendor/MSFT/Policy", "./Device/Vendor/MSFT/DMClient/Provider", "./Device/Vendor/MSFT/dmclient/Provider", "./Device/Vendor/MSFT/%44MClient/Provider", "./User/Vendor/MSFT/Enrollment", "./Device/Vendor/MSFT/Policy/../DMClient", "./Device/Vendor/MSFT/Policy/%2E%2E/DMClient", "./Device/Vendor/MSFT/Policy/a%2Fb", "./Device/Vendor/MSFT/Policy/a%252Fb", "./Device/Vendor/MSFT/Policy/a?prop=ACL", "./Device/Vendor/MSFT/Policy/*", "./Device/Vendor/MSFT/Policy/ä", "./Device/Vendor/MSFT/Policy/%c3%a4", "./Device/Vendor/MSFT/Policy//value"} {
		spec := cspTestPolicy()
		spec.URI = uri
		if _, _, err := encodeCSPRequest(spec); err == nil {
			t.Fatal("noncanonical or protected target accepted")
		}
	}
	invalid := []CSPCommandSpec{
		{Kind: "Status", URI: cspTestPolicyURI},
		{Kind: "Get", URI: cspTestPolicyURI, Data: &SyncMLData{Text: "hidden"}},
		{Kind: "Replace", URI: "./DevInfo/DevId", Format: "chr", Data: &SyncMLData{Text: "spoofed"}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "int", Data: &SyncMLData{Text: "07"}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "int", Data: &SyncMLData{Text: "2147483648"}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "bool", Data: &SyncMLData{Text: "1"}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "b64", Data: &SyncMLData{Text: "AB=="}},
		{Kind: "Replace", URI: cspTestPolicyURI, Format: "xml", Data: &SyncMLData{XML: `<broken>`}},
		{Kind: "Atomic", Commands: []CSPCommandSpec{{Kind: "Get", URI: "./DevInfo/Man"}}},
		{Kind: "Atomic", Commands: []CSPCommandSpec{{Kind: "Atomic", Commands: []CSPCommandSpec{cspTestPolicy()}}}},
		{Kind: "Atomic", Commands: []CSPCommandSpec{{Kind: "Add", URI: cspTestPolicyURI, Format: "int", Data: &SyncMLData{Text: "1"}}, cspTestPolicy()}},
		{Kind: "Sequence", Commands: []CSPCommandSpec{{Kind: "Sequence", Commands: []CSPCommandSpec{cspTestPolicy()}}}},
	}
	for _, spec := range invalid {
		if _, _, err := encodeCSPRequest(spec); err == nil {
			t.Fatal("invalid CSP command structure accepted")
		}
	}
	tooMany := CSPCommandSpec{Kind: "Sequence"}
	for n := 0; n < MaxCSPCommands; n++ {
		tooMany.Commands = append(tooMany.Commands, cspTestPolicy())
	}
	if _, _, err := encodeCSPRequest(tooMany); err == nil {
		t.Fatal("CSP command count limit bypassed")
	}
	large := cspTestPolicy()
	large.Format = "chr"
	large.Data = &SyncMLData{Text: strings.Repeat("x", MaxCSPRequestBytes)}
	if _, _, err := encodeCSPRequest(large); err == nil {
		t.Fatal("CSP encoded-size limit bypassed")
	}
}

func TestCSPResultChunksAndOutcomeClassification(t *testing.T) {
	for _, format := range []string{"chr", "b64"} {
		operation := cspOperationResult{Kind: "Get", URI: cspTestPolicyURI}
		size := uint64(4)
		first, last := "ab", "cd"
		if format == "b64" {
			first, last = "YWJ", "jZA=="
		}
		code, err := receiveCSPResult(&operation, nil, SyncMLItem{Meta: &SyncMLMeta{Format: format, Size: &size}, Data: &SyncMLData{Text: first}, MoreData: true})
		if err != nil || code != "213" || !operation.MoreData {
			t.Fatal("valid first result chunk rejected", err)
		}
		code, err = receiveCSPResult(&operation, nil, SyncMLItem{Data: &SyncMLData{Text: last}})
		if err != nil || code != "200" || operation.MoreData || cspResultLength(operation) != 4 {
			t.Fatal("result reconstruction changed byte size", err)
		}
	}
	for _, test := range []struct {
		status int
		kind   string
		result bool
		want   string
	}{{200, "Get", false, ""}, {200, "Get", true, "acknowledged"}, {200, "Replace", false, "acknowledged"}, {201, "Add", false, "acknowledged"}, {201, "Replace", false, "failed"}, {202, "Exec", false, "unknown"}, {214, "Exec", false, "failed"}, {216, "Replace", false, "failed"}, {500, "Replace", false, "failed"}} {
		state := &cspSessionCommand{Operations: []cspOperationResult{{Status: test.status, Kind: test.kind, HasResult: test.result}}}
		if cspOutcome(state) != test.want {
			t.Fatal("incorrect CSP outcome", test.status, test.kind)
		}
	}
}

func FuzzCSPCompiler(f *testing.F) {
	f.Add(cspTestPolicyURI, "Replace", "int", []byte("7"))
	f.Add("./User/Vendor/MSFT/WiFi/Profile/Test/WlanXml", "Replace", "chr", []byte("<synthetic>value</synthetic>"))
	f.Fuzz(func(t *testing.T, uri, kind, format string, value []byte) {
		spec := CSPCommandSpec{Kind: kind, URI: uri, Format: format, Data: &SyncMLData{Text: string(value)}}
		encoded, _, err := encodeCSPRequest(spec)
		if err != nil {
			return
		}
		command, _, err := decodeCSPRequest(encoded)
		if err != nil {
			t.Fatal("accepted request failed protected roundtrip", err)
		}
		if len(command.Items) != 1 || command.Items[0].Data == nil || !bytes.Equal([]byte(command.Items[0].Data.Text), value) {
			t.Fatal("accepted CSP value changed")
		}
	})
}

func cspTestTransition(t testing.TB) (ManagementDeviceIdentity, *syncMLDeviceRecord, *syncMLSession, *SyncMLMessage) {
	t.Helper()
	identity, record, session := syncMLTestTransition()
	first, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestInitial(identity, enrollmentTestOptions(), syncMLTestSecrets()))
	response, _ := syncMLTestAdvance(t, identity, record, session, syncMLTestReply(first))
	payload, _, err := encodeCSPRequest(CSPCommandSpec{Kind: "Sequence", Commands: []CSPCommandSpec{{Kind: "Get", URI: "./DevDetail/SwV"}, {Kind: "Atomic", Commands: []CSPCommandSpec{cspTestPolicy()}}}})
	if err != nil {
		t.Fatal(err)
	}
	command, _, err := decodeCSPRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	response.Commands = append(response.Commands, command)
	session.State.LastResponse = assignSyncMLResponseIDs(session, response)
	session.State.CSP = newCSPSessionCommand("55555555-5555-4555-8555-555555555555", response.Header.MessageID, response.Commands[1])
	session.Phase = "active"
	return identity, record, session, response
}

func cspTestPartial(response *SyncMLMessage) *SyncMLMessage {
	request := cspTestReply(response)
	request.Final = false
	size := uint64(4)
	for n := range request.Commands {
		c := &request.Commands[n]
		if c.Kind == "Results" {
			c.Items[0].Meta.Size = &size
			c.Items[0].Data.Text = "ab"
			c.Items[0].MoreData = true
		}
	}
	return request
}

func FuzzCSPResultTransition(f *testing.F) {
	f.Add("200", "", "chr", []byte("42"), false, false, uint64(2))
	f.Add("200", "", "chr", []byte("ab"), false, true, uint64(4))
	f.Add("200", "", "chr", []byte("cd"), true, false, uint64(4))
	f.Add("200", "", "b64", []byte("YWJjZA=="), false, false, uint64(4))
	f.Fuzz(func(t *testing.T, status, reference, format string, value []byte, continuation, more bool, size uint64) {
		if len(value) > MaxSyncMLBytes || len(reference) > 128 || len(format) > 128 || len(status) > 8 {
			return
		}
		identity, record, session, response := cspTestTransition(t)
		request := cspTestReply(response)
		var result SyncMLCommand
		for _, command := range request.Commands {
			if command.Kind == "Results" {
				result = command
			}
		}
		if continuation {
			continued, _ := syncMLTestAdvance(t, identity, record, session, cspTestPartial(response))
			request = cspTestReply(continued)
		} else {
			filtered := request.Commands[:0]
			for _, command := range request.Commands {
				if command.Kind != "Results" {
					if command.Kind == "Status" && command.CommandName == "Get" {
						command.Data.Text = status
					}
					filtered = append(filtered, command)
				}
			}
			request.Commands = filtered
		}
		result.ID = strconv.Itoa(len(request.Commands) + 10)
		if reference != "" {
			result.CommandRef = reference
		}
		result.Items[0].Data.Text = string(value)
		result.Items[0].Meta = &SyncMLMeta{Format: format}
		if !continuation {
			result.Items[0].Meta.Size = &size
		}
		result.Items[0].MoreData = more
		request.Commands = append(request.Commands, result)
		request.Final = !more
		wire, err := EncodeSyncML(request)
		if err != nil {
			return
		}
		request, err = ParseSyncML(wire)
		if err != nil {
			t.Fatal("structured CSP fixture lost codec roundtrip", err)
		}
		out, _, err := advanceSyncMLSession(identity, enrollmentTestOptions(), record, session, request, syncMLTestSecrets())
		if err != nil {
			if out != nil {
				t.Fatal("rejected CSP transition exposed response bytes")
			}
			return
		}
		if session.validate() != nil {
			t.Fatal("accepted CSP result produced invalid protected state")
		}
		encoded, err := EncodeSyncML(out)
		if err == nil {
			syncMLTestParsed(t, encoded)
		}
	})
}
