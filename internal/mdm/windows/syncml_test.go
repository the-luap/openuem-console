package windows

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const syncMLTestHeader = `<SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>1</SessionID><MsgID>1</MsgID><Target><LocURI>https://manage.example.test/windows/syncml</LocURI></Target><Source><LocURI>SYNTHETIC-DEVICE</LocURI><LocName>synthetic-account</LocName></Source><Cred><Meta><Format xmlns="syncml:metinf">b64</Format><Type xmlns="syncml:metinf">syncml:auth-md5</Type></Meta><Data>/koTkGRmuxqqJz9KIE1bAw==</Data></Cred><Meta><MaxMsgSize xmlns="syncml:metinf">65536</MaxMsgSize><MaxObjSize xmlns="syncml:metinf">1048576</MaxObjSize></Meta></SyncHdr>`

func syncMLTestDocument(body string) []byte {
	return []byte(`<SyncML xmlns="SYNCML:SYNCML1.2">` + syncMLTestHeader + `<SyncBody>` + body + `</SyncBody></SyncML>`)
}

const syncMLTestInitialization = `<Alert><CmdID>1</CmdID><Data>1201</Data></Alert><Alert><CmdID>2</CmdID><Data>1224</Data><Item><Meta><Type xmlns="syncml:metinf">com.microsoft/MDM/LoginStatus</Type></Meta><Data>user</Data></Item></Alert><Replace><CmdID>3</CmdID><Item><Source><LocURI>./DevInfo/DevId</LocURI></Source><Data>SYNTHETIC-DEVICE</Data></Item><Item><Source><LocURI>./DevInfo/Man</LocURI></Source><Data>Synthetic vendor</Data></Item><Item><Source><LocURI>./DevInfo/Mod</LocURI></Source><Data>Synthetic Windows device</Data></Item><Item><Source><LocURI>./DevInfo/DmV</LocURI></Source><Data>1.3</Data></Item><Item><Source><LocURI>./DevInfo/Lang</LocURI></Source><Data>en-US</Data></Item></Replace><Final/>`

func TestSyncMLInitializationAndIndependentWireEncoding(t *testing.T) {
	input := syncMLTestDocument(syncMLTestInitialization)
	m, err := ParseSyncML(input)
	if err != nil || !m.Final || len(m.Commands) != 3 || m.Header.SessionID != "1" || m.Header.MessageID != "1" || m.Header.Source.URI != "SYNTHETIC-DEVICE" || m.Header.Credential.Digest != "/koTkGRmuxqqJz9KIE1bAw==" || *m.Header.Meta.MaxMessageSize != 65536 || *m.Header.Meta.MaxObjectSize != 1048576 {
		t.Fatal("initialization shape was not retained", err)
	}
	if m.Commands[0].Data.Text != "1201" || m.Commands[1].Items[0].Meta.Type != "com.microsoft/MDM/LoginStatus" || len(m.Commands[2].Items) != 5 || m.Commands[2].Items[2].Data.Text != "Synthetic Windows device" {
		t.Fatal("ordered initialization commands or inventory values changed")
	}
	encoded, err := EncodeSyncML(m)
	if err != nil {
		t.Fatal(err)
	}
	var wire policyWireNode
	if err := xml.Unmarshal(encoded, &wire); err != nil || wire.Name != (xml.Name{Space: syncMLNS, Local: "SyncML"}) {
		t.Fatal("invalid independently decoded SyncML XML", err)
	}
	header := wireChild(t, &wire, syncMLNS, "SyncHdr")
	credential := wireChild(t, header, syncMLNS, "Cred")
	meta := wireChild(t, credential, syncMLNS, "Meta")
	if wireChild(t, meta, syncMLMetaNS, "Type").Text != syncMLDigestType || wireChild(t, credential, syncMLNS, "Data").Text != m.Header.Credential.Digest {
		t.Fatal("credential namespace or encoding changed")
	}
	body := wireChild(t, &wire, syncMLNS, "SyncBody")
	if len(body.Children) != 4 || body.Children[0].Name.Local != "Alert" || body.Children[2].Name.Local != "Replace" || body.Children[3].Name.Local != "Final" {
		t.Fatal("encoder reordered commands")
	}
	again, err := ParseSyncML(encoded)
	if err != nil || !reflect.DeepEqual(m, again) {
		t.Fatal("codec changed the typed message", err)
	}
}

func TestSyncMLNamespaceAliasesAuthenticationAndOpaqueIDs(t *testing.T) {
	base := string(syncMLTestDocument(syncMLTestInitialization))
	for _, input := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>` + base,
		"\ufeff" + base,
		strings.ReplaceAll(strings.Replace(base, `<SyncML xmlns="SYNCML:SYNCML1.2">`, `<s:SyncML xmlns:s="SYNCML:SYNCML1.2" xmlns="SYNCML:SYNCML1.2">`, 1), `</SyncML>`, `</s:SyncML>`),
		strings.ReplaceAll(base, `<Type xmlns="syncml:metinf">syncml:auth-md5</Type>`, `<m:Type xmlns:m="syncml:metinf">syncml:auth-md5</m:Type>`),
	} {
		if _, err := ParseSyncML([]byte(input)); err != nil {
			t.Fatal("valid namespace or XML declaration rejected", err)
		}
	}
	wrapped := strings.Replace(base, `<Meta><MaxMsgSize xmlns="syncml:metinf">65536</MaxMsgSize><MaxObjSize xmlns="syncml:metinf">1048576</MaxObjSize></Meta>`, `<Meta><MetInf xmlns="syncml:metinf"><MaxMsgSize>65536</MaxMsgSize><MaxObjSize>1048576</MaxObjSize></MetInf></Meta>`, 1)
	wrapped = strings.ReplaceAll(wrapped, `<SessionID>1</SessionID>`, `<SessionID>opaque:session-A</SessionID>`)
	wrapped = strings.ReplaceAll(wrapped, `<MsgID>1</MsgID>`, `<MsgID>18446744073709551615</MsgID>`)
	wrapped = strings.ReplaceAll(wrapped, `<CmdID>1</CmdID>`, `<CmdID>opaque-command</CmdID>`)
	m, err := ParseSyncML([]byte(wrapped))
	if err != nil || m.Header.SessionID != "opaque:session-A" || m.Header.MessageID != "18446744073709551615" || m.Commands[0].ID != "opaque-command" || *m.Header.Meta.MaxObjectSize != 1048576 {
		t.Fatal("opaque correlation identifiers or MetInf wrapper changed", err)
	}
	// Missing credentials are representable so the session service can challenge;
	// their absence must never be mistaken for successful authentication.
	start := strings.Index(base, "<Cred>")
	end := strings.Index(base, "</Cred>") + len("</Cred>")
	without := base[:start] + base[end:]
	m, err = ParseSyncML([]byte(without))
	if err != nil || m.Header.Credential != nil {
		t.Fatal("credential-free challenge request misrepresented", err)
	}
}

func TestSyncMLStatusChallengeResultsAndCommandVocabulary(t *testing.T) {
	status := `<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>0</CmdRef><Cmd>SyncHdr</Cmd><TargetRef>https://manage.example.test/windows/syncml</TargetRef><SourceRef>SYNTHETIC-DEVICE</SourceRef><Chal><Meta><Type xmlns="syncml:metinf">syncml:auth-md5</Type><Format xmlns="syncml:metinf">b64</Format><NextNonce xmlns="syncml:metinf">AAECAwQFBgcICQoLDA0ODw==</NextNonce></Meta></Chal><Data>212</Data></Status>`
	results := `<Results><CmdID>2</CmdID><MsgRef>1</MsgRef><CmdRef>4</CmdRef><Meta><Format xmlns="syncml:metinf">chr</Format><Type xmlns="syncml:metinf">text/plain</Type><Size xmlns="syncml:metinf">0</Size></Meta><Item><Source><LocURI>./DevDetail/SwV</LocURI></Source><Data>10.0.synthetic</Data><MoreData/></Item></Results>`
	m, err := ParseSyncML(syncMLTestDocument(status + results + `<Final/>`))
	if err != nil || m.Commands[0].Data.Text != "212" || m.Commands[0].Challenge.NextNonce != "AAECAwQFBgcICQoLDA0ODw==" || !m.Commands[1].Items[0].MoreData || *m.Commands[1].Meta.Size != 0 {
		t.Fatal("status, challenge or partial result changed", err)
	}
	encoded, err := EncodeSyncML(m)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseSyncML(encoded)
	if err != nil || !reflect.DeepEqual(m, again) {
		t.Fatal("authentication/result codec lost values", err)
	}
	for _, body := range []string{
		strings.Replace(status, `<CmdRef>0</CmdRef>`, "", 1),
		`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef></CmdRef><Cmd>Unknown</Cmd><Data>400</Data></Status>`,
		`<Alert><CmdID>1</CmdID><Data>1226</Data><Item><Meta><Type xmlns="syncml:metinf">com.example/operation</Type><Mark xmlns="syncml:metinf">critical</Mark></Meta><Data>failed</Data></Item></Alert>`,
		`<Final/>`,
	} {
		m, err := ParseSyncML(syncMLTestDocument(body))
		if err != nil {
			t.Fatal("valid status/alert/package boundary rejected", err)
		}
		if _, err := EncodeSyncML(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"Add", "Replace", "Delete", "Get", "Exec"} {
		m.Commands = []SyncMLCommand{{Kind: kind, ID: "command", Meta: &SyncMLMeta{Format: "chr", Version: "1", EMI: []string{"one", "two"}}, Items: []SyncMLItem{{Target: &SyncMLLocation{URI: "./Vendor/MSFT/Synthetic/Value"}, Data: &SyncMLData{Text: "synthetic <value> & data"}}}}}
		encoded, err := EncodeSyncML(m)
		if err != nil {
			t.Fatal("command vocabulary rejected", kind, err)
		}
		again, err := ParseSyncML(encoded)
		if err != nil || !reflect.DeepEqual(m, again) {
			t.Fatal("command data or metadata changed", kind, err)
		}
	}
	m.Commands = []SyncMLCommand{{Kind: "Sequence", ID: "sequence", Commands: []SyncMLCommand{{Kind: "Atomic", ID: "atomic", Commands: m.Commands}}}}
	if encoded, err := EncodeSyncML(m); err != nil {
		t.Fatal(err)
	} else if again, err := ParseSyncML(encoded); err != nil || !reflect.DeepEqual(m, again) {
		t.Fatal("nested command ordering changed", err)
	}
}

func TestSyncMLPreservesDataAndSelfContainedMarkup(t *testing.T) {
	for _, data := range []struct{ wire, text, markup string }{
		{`<Data/>`, "", ""},
		{`<Data>  first&#10;second &amp; third  </Data>`, "  first\nsecond & third  ", ""},
		{`<Data><![CDATA[<policy value="synthetic"/>]]></Data>`, `<policy value="synthetic"/>`, ""},
		{`<Data>before<p:policy xmlns:p="urn:synthetic" name="a &amp; b"><child xmlns="urn:child"/></p:policy>after</Data>`, "", `before<p:policy xmlns:p="urn:synthetic" name="a &amp; b"><child xmlns="urn:child"/></p:policy>after`},
		{`<Data><policy xmlns="">unqualified payload</policy></Data>`, "", `<policy xmlns="">unqualified payload</policy>`},
	} {
		m, err := ParseSyncML(syncMLTestDocument(`<Replace><CmdID>1</CmdID><Item><Source><LocURI>./Synthetic</LocURI></Source>` + data.wire + `</Item></Replace><Final/>`))
		if err != nil || m.Commands[0].Items[0].Data.Text != data.text || m.Commands[0].Items[0].Data.XML != data.markup {
			t.Fatal("opaque data was normalized or lost", err)
		}
		encoded, err := EncodeSyncML(m)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseSyncML(encoded)
		if err != nil || !reflect.DeepEqual(m, again) {
			t.Fatal("data meaning changed after encoding", err)
		}
	}
	body := `<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>4</CmdRef><Cmd>Replace</Cmd><Data xmlns:m="http://schemas.microsoft.com/MobileDevice/MDM" m:originalerror="0x86000002">500</Data></Status><Final/>`
	m, err := ParseSyncML(syncMLTestDocument(body))
	if err != nil || m.Commands[0].Data.Text != "500" || m.Commands[0].Data.OriginalError != "0x86000002" {
		t.Fatal("native failure detail changed the status", err)
	}
	if encoded, err := EncodeSyncML(m); err != nil {
		t.Fatal(err)
	} else if again, err := ParseSyncML(encoded); err != nil || !reflect.DeepEqual(m, again) {
		t.Fatal("native error hint did not survive encoding", err)
	}
}

func TestSyncMLRejectsAmbiguityUnsafeMarkupAndWrongAuthentication(t *testing.T) {
	base := string(syncMLTestDocument(syncMLTestInitialization))
	for name, input := range map[string]string{
		"empty":                      "",
		"doctype":                    `<!DOCTYPE SyncML [<!ENTITY attack SYSTEM "file:///never-read">]>` + base,
		"processing instruction":     strings.Replace(base, `<SyncBody>`, `<SyncBody><?unsafe value?>`, 1),
		"root namespace":             strings.Replace(base, syncMLNS, "urn:wrong", 1),
		"header namespace":           strings.Replace(base, `<SyncHdr>`, `<SyncHdr xmlns="urn:wrong">`, 1),
		"duplicate header":           strings.Replace(base, `</SyncHdr>`, `</SyncHdr>`+syncMLTestHeader, 1),
		"duplicate source":           strings.Replace(base, `</Source>`, `</Source><Source><LocURI>other</LocURI></Source>`, 1),
		"foreign duplicate":          strings.Replace(base, `</Source>`, `</Source><Source xmlns="urn:wrong"><LocURI>other</LocURI></Source>`, 1),
		"unknown header":             strings.Replace(base, `</SyncHdr>`, `<TenantID>2</TenantID></SyncHdr>`, 1),
		"NoResp":                     strings.Replace(base, `</SyncHdr>`, `<NoResp/></SyncHdr>`, 1),
		"protocol downgrade":         strings.Replace(base, `DM/1.2`, `DM/1.1`, 1),
		"DTD downgrade":              strings.Replace(base, `<VerDTD>1.2`, `<VerDTD>1.1`, 1),
		"empty session":              strings.Replace(base, `<SessionID>1`, `<SessionID>`, 1),
		"space identifier":           strings.Replace(base, `<MsgID>1`, `<MsgID> 1`, 1),
		"nonnumeric message":         strings.Replace(base, `<MsgID>1`, `<MsgID>opaque`, 1),
		"zero message":               strings.Replace(base, `<MsgID>1`, `<MsgID>0`, 1),
		"numeric message alias":      strings.Replace(base, `<MsgID>1`, `<MsgID>01`, 1),
		"duplicate command":          strings.Replace(base, `<CmdID>2`, `<CmdID>1`, 1),
		"reserved command":           strings.Replace(base, `<CmdID>1`, `<CmdID>0`, 1),
		"command credential":         strings.Replace(base, `<CmdID>3</CmdID>`, `<CmdID>3</CmdID><Cred/>`, 1),
		"foreign command":            strings.Replace(base, `<Replace>`, `<Replace xmlns="urn:wrong">`, 1),
		"unsupported command":        strings.ReplaceAll(strings.ReplaceAll(base, `<Replace>`, `<Copy>`), `</Replace>`, `</Copy>`),
		"duplicate final":            strings.Replace(base, `<Final/>`, `<Final/><Final/>`, 1),
		"early final":                strings.Replace(base, `<SyncBody>`, `<SyncBody><Final/>`, 1),
		"nonempty final":             strings.Replace(base, `<Final/>`, `<Final> </Final>`, 1),
		"mixed body":                 strings.Replace(base, `<SyncBody>`, `<SyncBody>not a command`, 1),
		"basic auth":                 strings.Replace(base, syncMLDigestType, "syncml:auth-basic", 1),
		"wrong auth format":          strings.Replace(base, `>b64<`, `>chr<`, 1),
		"credential padding":         strings.Replace(base, `/koTkGRmuxqqJz9KIE1bAw==`, `/koTkGRmuxqqJz9KIE1bAx==`, 1),
		"credential whitespace":      strings.Replace(base, `/koTkGRmuxqqJz9KIE1bAw==`, `/koTkGRmuxqqJz9KIE1bAw==&#10;`, 1),
		"duplicate metadata":         strings.Replace(base, `</MaxMsgSize>`, `</MaxMsgSize><MaxMsgSize xmlns="syncml:metinf">1</MaxMsgSize>`, 1),
		"metadata namespace":         strings.Replace(base, `<MaxMsgSize xmlns="syncml:metinf">`, `<MaxMsgSize>`, 1),
		"unknown metadata":           strings.Replace(base, `</MaxMsgSize>`, `</MaxMsgSize><Danger xmlns="syncml:metinf">1</Danger>`, 1),
		"numeric alias":              strings.Replace(base, `>65536<`, `>065536<`, 1),
		"zero maximum":               strings.Replace(base, `>65536<`, `>0<`, 1),
		"large maximum":              strings.Replace(base, `>65536<`, `>4294967296<`, 1),
		"inherited markup namespace": strings.Replace(base, `<Data>user</Data>`, `<Data><Policy>unbound</Policy></Data>`, 1),
		"data attribute":             strings.Replace(base, `<Data>user</Data>`, `<Data tenant="2">user</Data>`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseSyncML([]byte(input)); !errors.Is(err, ErrSyncML) || got != nil {
				t.Fatal("invalid or ambiguous message accepted", err)
			}
		})
	}
}

func TestSyncMLCommandRequirementsAndNestedIDs(t *testing.T) {
	for _, body := range []string{
		`<Get><CmdID>1</CmdID></Get>`, `<Atomic><CmdID>1</CmdID></Atomic>`,
		`<Exec><CmdID>1</CmdID><Item/><Item/></Exec>`,
		`<Exec><CmdID>1</CmdID><Correlator>unsupported</Correlator><Item/></Exec>`,
		`<Alert><CmdID>1</CmdID><Data>1226</Data><Correlator>unsupported</Correlator></Alert>`,
		`<Sequence><CmdID>1</CmdID><Sequence><CmdID>2</CmdID><Get><CmdID>3</CmdID><Item/></Get></Sequence></Sequence>`,
		`<Sequence><CmdID>1</CmdID><Get><CmdID>1</CmdID><Item/></Get></Sequence>`,
		`<Results><CmdID>1</CmdID><CmdRef>2</CmdRef><Item/></Results>`,
		`<Results><CmdID>1</CmdID><MsgRef>1</MsgRef><Item/></Results>`,
		`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><Cmd>Get</Cmd><Data>200</Data></Status>`,
		`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>2</CmdRef><Data>200</Data></Status>`,
		`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><Cmd>SyncHdr</Cmd><Data>0200</Data></Status>`,
		`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><Cmd>SyncHdr</Cmd><Data>99</Data></Status>`,
		`<Alert><CmdID>1</CmdID><Data>200</Data></Alert>`,
		`<Alert><CmdID>1</CmdID><Data>1201</Data><Item><MoreData/></Item></Alert>`,
		`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><Cmd>SyncHdr</Cmd><Chal><Meta><Type xmlns="syncml:metinf">syncml:auth-md5</Type><Format xmlns="syncml:metinf">b64</Format><NextNonce xmlns="syncml:metinf">c2hvcnQ=</NextNonce></Meta></Chal><Data>401</Data></Status>`,
	} {
		if got, err := ParseSyncML(syncMLTestDocument(body)); !errors.Is(err, ErrSyncML) || got != nil {
			t.Fatal("invalid command requirements accepted", err)
		}
	}
}

func TestSyncMLBoundsAndEncoderRejection(t *testing.T) {
	m, err := ParseSyncML(syncMLTestDocument(`<Replace><CmdID>1</CmdID><Item><Data>value</Data></Item></Replace><Final/>`))
	if err != nil {
		t.Fatal(err)
	}
	m.Commands[0].Items[0].Data.Text = strings.Repeat("a", MaxSyncMLDataBytes)
	if _, err := EncodeSyncML(m); err != nil {
		t.Fatal("exact data boundary rejected", err)
	}
	m.Commands[0].Items[0].Data.Text += "a"
	if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
		t.Fatal("oversized data encoded")
	}
	input := syncMLTestDocument(`<Alert><CmdID>1</CmdID><Data>1201</Data></Alert><Final/>`)
	padded := append(bytes.Clone(input), bytes.Repeat([]byte{' '}, MaxSyncMLBytes-len(input))...)
	if _, err := ParseSyncML(padded); err != nil {
		t.Fatal("exact document boundary rejected", err)
	}
	if got, err := ParseSyncML(append(padded, ' ')); !errors.Is(err, ErrSyncML) || got != nil {
		t.Fatal("oversized document accepted")
	}
	commands := ""
	for n := 1; n <= MaxSyncMLCommands; n++ {
		commands += `<Alert><CmdID>` + strconv.Itoa(n) + `</CmdID><Data>1201</Data></Alert>`
	}
	if _, err := ParseSyncML(syncMLTestDocument(commands)); err != nil {
		t.Fatal("exact command count rejected", err)
	}
	if got, err := ParseSyncML(syncMLTestDocument(commands + `<Alert><CmdID>overflow</CmdID><Data>1201</Data></Alert>`)); !errors.Is(err, ErrSyncML) || got != nil {
		t.Fatal("command limit bypassed")
	}
	items := strings.Repeat(`<Item/>`, MaxSyncMLItems)
	if _, err := ParseSyncML(syncMLTestDocument(`<Get><CmdID>1</CmdID>` + items + `</Get>`)); err != nil {
		t.Fatal("exact item count rejected", err)
	}
	if got, err := ParseSyncML(syncMLTestDocument(`<Get><CmdID>1</CmdID>` + items + `<Item/></Get>`)); !errors.Is(err, ErrSyncML) || got != nil {
		t.Fatal("item limit bypassed")
	}
	if data, err := EncodeSyncML(nil); !errors.Is(err, ErrSyncML) || data != nil {
		t.Fatal("nil message encoded")
	}
	for _, data := range []SyncMLData{{XML: `<policy/>`}, {Text: "value", XML: `<policy xmlns=""/>`}, {XML: `<!DOCTYPE data><policy xmlns=""/>`}, {Text: "value", OriginalError: "wrong"}} {
		m.Commands[0].Items[0].Data = &data
		if got, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || got != nil {
			t.Fatal("invalid constructed payload encoded")
		}
	}
	m.Commands[0].Items[0].Data = &SyncMLData{Text: "value"}
	for n := 0; n < 9; n++ {
		m.Commands = []SyncMLCommand{{Kind: "Atomic", ID: "group-" + strconv.Itoa(n), Commands: m.Commands}}
	}
	if got, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || got != nil {
		t.Fatal("deep constructed group encoded")
	}
}

func TestSyncMLDiagnosticsAndDefaultSerializationProtectData(t *testing.T) {
	m, err := ParseSyncML(syncMLTestDocument(syncMLTestInitialization))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{*m, m.Header, m.Header.Source, *m.Header.Credential, *m.Header.Meta, m.Commands[2], m.Commands[2].Items[0], *m.Commands[2].Items[0].Data} {
		for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if !strings.HasPrefix(formatted, "[protected Windows SyncML") {
				t.Fatal("formatting exposed protected payload")
			}
		}
		for _, marshal := range []func(any) ([]byte, error){json.Marshal, xml.Marshal} {
			encoded, err := marshal(value)
			if err != nil || bytes.Contains(encoded, []byte("SYNTHETIC-DEVICE")) || bytes.Contains(encoded, []byte("synthetic-account")) || bytes.Contains(encoded, []byte(m.Header.Credential.Digest)) {
				t.Fatal("default serialization exposed payload", err)
			}
		}
	}
}

func TestSyncMLGlobalLimitsAndIndependentInputOwnership(t *testing.T) {
	input := syncMLTestDocument(`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><Cmd>SyncHdr</Cmd><Data>212</Data></Status><Final/>`)
	m, err := ParseSyncML(input)
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	if m.Header.Source.URI != "SYNTHETIC-DEVICE" || m.Header.Credential.Digest != "/koTkGRmuxqqJz9KIE1bAw==" || m.Commands[0].Data.Text != "212" {
		t.Fatal("parsed values alias mutable request bytes")
	}
	refs := make([]string, MaxSyncMLReferences)
	for n := range refs {
		refs[n] = "./Synthetic/" + strconv.Itoa(n)
	}
	m.Commands[0].TargetRefs = refs
	if data, err := EncodeSyncML(m); err != nil {
		t.Fatal("exact reference limit rejected", err)
	} else if parsed, err := ParseSyncML(data); err != nil || len(parsed.Commands[0].TargetRefs) != MaxSyncMLReferences {
		t.Fatal("reference count changed", err)
	}
	m.Commands[0].SourceRefs = []string{"overflow"}
	if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
		t.Fatal("global reference limit bypassed")
	}
	m.Commands[0].SourceRefs, m.Commands[0].TargetRefs = nil, nil
	for n := 2; n <= MaxSyncMLCommands; n++ {
		m.Commands = append(m.Commands, SyncMLCommand{Kind: "Alert", ID: strconv.Itoa(n), Data: &SyncMLData{Text: "1201"}})
	}
	if _, err := EncodeSyncML(m); err != nil {
		t.Fatal("encoder rejected exact command count", err)
	}
	m.Commands = append(m.Commands, SyncMLCommand{Kind: "Alert", ID: "overflow", Data: &SyncMLData{Text: "1201"}})
	if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
		t.Fatal("encoder command limit bypassed")
	}
	m.Commands = []SyncMLCommand{{Kind: "Replace", ID: "1", Items: []SyncMLItem{{Data: &SyncMLData{Text: "small"}}}}}
	for _, set := range []func(*SyncMLMeta){
		func(meta *SyncMLMeta) { m.Header.Meta = meta },
		func(meta *SyncMLMeta) { m.Commands[0].Meta = meta },
		func(meta *SyncMLMeta) { m.Commands[0].Items[0].Meta = meta },
	} {
		set(&SyncMLMeta{EMI: make([]string, 17)})
		if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
			t.Fatal("oversized metadata collection encoded")
		}
		set(nil)
	}
	// Every individual Data remains valid, but the encoded document exceeds the
	// transport bound. The encoder must suppress all partially generated bytes.
	m.Commands[0].Items = nil
	for n := 0; n < 5; n++ {
		m.Commands[0].Items = append(m.Commands[0].Items, SyncMLItem{Data: &SyncMLData{Text: strings.Repeat("a", MaxSyncMLDataBytes)}})
	}
	if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
		t.Fatal("encoder returned partial or oversized message")
	}
}

func TestSyncMLEncoderNeverReplacesInvalidCharacters(t *testing.T) {
	for _, value := range []string{"invalid\x00", "invalid\x0b", "invalid\ufffe", "invalid\uffff", string([]byte{0xff})} {
		for _, field := range []string{"data", "name", "metadata", "identifier"} {
			m, err := ParseSyncML(syncMLTestDocument(`<Replace><CmdID>1</CmdID><Item><Data>value</Data></Item></Replace><Final/>`))
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "data":
				m.Commands[0].Items[0].Data.Text = value
			case "name":
				m.Header.Source.Name = value
			case "metadata":
				m.Header.Meta.Type = value
			case "identifier":
				m.Header.SessionID = value
			}
			if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
				t.Fatal("encoder silently replaced invalid XML text", field)
			}
		}
	}
}

func TestSyncMLEncoderUsesProtocolFieldOrder(t *testing.T) {
	m, err := ParseSyncML(syncMLTestDocument(`<Results><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>4</CmdRef><TargetRef>./Target</TargetRef><SourceRef>./Source</SourceRef><Meta><Format xmlns="syncml:metinf">chr</Format></Meta><Item><Data>value</Data></Item></Results><Final/>`))
	if err != nil {
		t.Fatal(err)
	}
	number := uint64(1)
	m.Header.Meta = &SyncMLMeta{Format: "chr", Type: "text/plain", Mark: "value", Size: &number, Version: "1", NextNonce: "AAECAwQFBgcICQoLDA0ODw==", MaxMessageSize: &number, MaxObjectSize: &number, EMI: []string{"one", "two"}}
	encoded, err := EncodeSyncML(m)
	if err != nil {
		t.Fatal(err)
	}
	var root policyWireNode
	if err := xml.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	meta := wireChild(t, wireChild(t, &root, syncMLNS, "SyncHdr"), syncMLNS, "Meta")
	for n, name := range []string{"Format", "Type", "Mark", "Size", "Version", "NextNonce", "MaxMsgSize", "MaxObjSize", "EMI", "EMI"} {
		if len(meta.Children) != 10 || meta.Children[n].Name != (xml.Name{Space: syncMLMetaNS, Local: name}) {
			t.Fatal("metadata order differs from the MetaInfo DTD")
		}
	}
	results := wireChild(t, wireChild(t, &root, syncMLNS, "SyncBody"), syncMLNS, "Results")
	for n, name := range []string{"CmdID", "MsgRef", "CmdRef", "Meta", "TargetRef", "SourceRef", "Item"} {
		if len(results.Children) != 7 || results.Children[n].Name != (xml.Name{Space: syncMLNS, Local: name}) {
			t.Fatal("Results order differs from the representation DTD")
		}
	}
	m.Header.Meta.EMI = []string{""}
	if data, err := EncodeSyncML(m); !errors.Is(err, ErrSyncML) || data != nil {
		t.Fatal("encoder silently omitted invalid empty metadata")
	}
}

func FuzzSyncMLDataCodec(f *testing.F) {
	f.Add("  text & <markup>\n", "synthetic-name")
	f.Add("\x00\xff", "invalid")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, text, name string) {
		m := &SyncMLMessage{Header: SyncMLHeader{SessionID: "1", MessageID: "1", Target: SyncMLLocation{URI: "https://manage.example.test/windows/syncml"}, Source: SyncMLLocation{URI: "synthetic-device", Name: name}}, Commands: []SyncMLCommand{{Kind: "Replace", ID: "1", Items: []SyncMLItem{{Data: &SyncMLData{Text: text}}}}}, Final: true}
		encoded, err := EncodeSyncML(m)
		if err != nil {
			return
		}
		parsed, err := ParseSyncML(encoded)
		if err != nil || parsed.Header.Source.Name != name || parsed.Commands[0].Items[0].Data.Text != text {
			t.Fatal("encoding changed payload or source characters", err)
		}
	})
}

func FuzzSyncML(f *testing.F) {
	f.Add(syncMLTestDocument(syncMLTestInitialization))
	f.Add(syncMLTestDocument(`<Status><CmdID>1</CmdID><MsgRef>1</MsgRef><CmdRef>0</CmdRef><Cmd>SyncHdr</Cmd><Data>212</Data></Status><Final/>`))
	f.Add(syncMLTestDocument(`<Replace><CmdID>1</CmdID><Item><Data><p xmlns="urn:synthetic">text<c/>tail</p></Data></Item></Replace><Final/>`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := ParseSyncML(data)
		if err != nil {
			return
		}
		encoded, err := EncodeSyncML(message)
		// Canonical namespace spelling/escaping may exceed the output byte limit.
		if err != nil {
			if len(data) < 16<<10 {
				t.Fatal("small accepted message could not be encoded", err)
			}
			return
		}
		again, err := ParseSyncML(encoded)
		if err != nil || !reflect.DeepEqual(message, again) {
			t.Fatal("accepted SyncML changed meaning during encoding", err)
		}
	})
}
