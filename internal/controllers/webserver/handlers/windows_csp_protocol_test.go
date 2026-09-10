package handlers

import (
	"bytes"
	"context"
	"crypto/md5" // Synthetic OMA DM DIGEST peer, matching the protocol's MD5 requirement.
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// This synthetic peer uses public enrollment and SyncML handlers to produce
// genuine stored outcomes. It neither changes a host certificate store nor opens
// a network listener. TLS state is supplied by httptest, not a real handshake.
func windowsCSPConsolePeer(t *testing.T, h *Handler, ctx context.Context, scope access.Scope) (string, func(windows.CSPCommandSpec, string) *windows.CSPCommandDetail) {
	t.Helper()
	id, deliver, _ := windowsConsoleProtocolPeer(t, h, ctx, scope)
	return id, deliver
}

func windowsConsoleProtocolPeer(t *testing.T, h *Handler, ctx context.Context, scope access.Scope) (string, func(windows.CSPCommandSpec, string) *windows.CSPCommandDetail, func()) {
	t.Helper()
	invitation, credential, err := h.Windows.CreateEnrollmentInvitation(ctx, "organization-admin", scope, "csp-console-peer@example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := os.ReadFile("../../../mdm/windows/testdata/enrollment-csr.der")
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.Windows.EnrollWindows(ctx, &windows.WSTEPRequest{MessageID: "urn:uuid:" + uuid.NewString(), Credential: *credential, CSRDER: csr, Context: []windows.EnrollmentContextItem{
		{Name: "OSEdition", Value: "48"}, {Name: "OSVersion", Value: "10.0.26100.0"}, {Name: "ApplicationVersion", Value: "10.0.26100.0"}, {Name: "DeviceName", Value: "Synthetic CSP <script>peer</script>"}, {Name: "DeviceID", Value: "synthetic-csp-peer"}, {Name: "DeviceType", Value: "CIMClient_Windows"}, {Name: "EnrollmentType", Value: "Full"},
	}}, h.WindowsOptions)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(response))
	var document []byte
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "BinarySecurityToken" {
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				t.Fatal(err)
			}
			document, err = base64.StdEncoding.DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	defer clear(document)
	type characteristic struct {
		Type       string `xml:"type,attr"`
		Parameters []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"parm"`
		Children []characteristic `xml:"characteristic"`
	}
	var provisioning struct {
		Children []characteristic `xml:"characteristic"`
	}
	if err := xml.Unmarshal(document, &provisioning); err != nil {
		t.Fatal(err)
	}
	var deviceID, secret, nonce string
	var visit func([]characteristic)
	visit = func(nodes []characteristic) {
		for _, node := range nodes {
			p := map[string]string{}
			for _, parameter := range node.Parameters {
				p[parameter.Name] = parameter.Value
			}
			if node.Type == "APPAUTH" && p["AAUTHLEVEL"] == "APPSRV" {
				deviceID, secret, nonce = p["AAUTHNAME"], p["AAUTHSECRET"], p["AAUTHDATA"]
			}
			visit(node.Children)
		}
	}
	visit(provisioning.Children)
	if deviceID == "" || secret == "" || nonce == "" {
		t.Fatal("synthetic enrollment omitted bootstrap")
	}
	var der []byte
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT c.certificate FROM mdm_windows_enrollments e JOIN mdm_windows_device_certificates c ON c.id=e.certificate_id WHERE e.invitation_id=$1 AND e.device_id=$2`, invitation.ID, deviceID).Scan(&der); err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := windows.NewSyncMLHandler(h.Windows, h.WindowsOptions)
	if err != nil {
		t.Fatal(err)
	}
	process := func(message *windows.SyncMLMessage) *windows.SyncMLMessage {
		t.Helper()
		data, err := windows.EncodeSyncML(message)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", h.WindowsOptions.ManagementURL, bytes.NewReader(data)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/vnd.syncml.dm+xml")
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}
		w := httptest.NewRecorder()
		transport.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("synthetic CSP exchange failed", message.Header.MessageID, w.Code)
		}
		parsed, err := windows.ParseSyncML(w.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range parsed.Commands {
			if command.Challenge != nil && command.Challenge.NextNonce != "" {
				nonce = command.Challenge.NextNonce
			}
		}
		return parsed
	}
	deliver := func(spec windows.CSPCommandSpec, status string) *windows.CSPCommandDetail {
		t.Helper()
		queued, err := h.Windows.EnqueueCSPCommand(ctx, "organization-admin", scope, deviceID, uuid.NewString(), spec, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		rawNonce, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			t.Fatal(err)
		}
		inner := md5.Sum([]byte(deviceID + ":" + secret))
		outer := md5.Sum(append([]byte(base64.StdEncoding.EncodeToString(inner[:])+":"), rawNonce...))
		maximum := uint64(5000)
		initial := &windows.SyncMLMessage{Header: windows.SyncMLHeader{SessionID: "1", MessageID: "1", Source: windows.SyncMLLocation{URI: "urn:uuid:synthetic-csp-console-peer", Name: deviceID}, Target: windows.SyncMLLocation{URI: h.WindowsOptions.ManagementURL}, Credential: &windows.SyncMLCredential{Digest: base64.StdEncoding.EncodeToString(outer[:])}, Meta: &windows.SyncMLMeta{MaxMessageSize: &maximum}}, Final: true}
		initial.Commands = []windows.SyncMLCommand{{Kind: "Alert", ID: "1", Data: &windows.SyncMLData{Text: "1224"}, Items: []windows.SyncMLItem{{Meta: &windows.SyncMLMeta{Type: "com.microsoft/MDM/LoginStatus"}, Data: &windows.SyncMLData{Text: "user"}}}}}
		info := windows.SyncMLCommand{Kind: "Replace", ID: "2"}
		for i, uri := range []string{"./DevInfo/DevId", "./DevInfo/Man", "./DevInfo/Mod", "./DevInfo/DmV", "./DevInfo/Lang"} {
			info.Items = append(info.Items, windows.SyncMLItem{Source: &windows.SyncMLLocation{URI: uri}, Meta: &windows.SyncMLMeta{Format: "chr"}, Data: &windows.SyncMLData{Text: []string{"synthetic-csp-peer", "Synthetic manufacturer", "Synthetic model", "1.2", "en-US"}[i]}})
		}
		initial.Commands = append(initial.Commands, info)
		reply := func(response *windows.SyncMLMessage, outcome string) *windows.SyncMLMessage {
			n, _ := strconv.Atoi(response.Header.MessageID)
			message := &windows.SyncMLMessage{Header: windows.SyncMLHeader{SessionID: response.Header.SessionID, MessageID: strconv.Itoa(n + 1), Source: response.Header.Target, Target: response.Header.Source}, Final: true}
			message.Commands = []windows.SyncMLCommand{{Kind: "Status", ID: "1", MessageRef: response.Header.MessageID, CommandRef: "0", CommandName: "SyncHdr", Data: &windows.SyncMLData{Text: "212"}}}
			var acknowledge func([]windows.SyncMLCommand)
			acknowledge = func(commands []windows.SyncMLCommand) {
				for _, command := range commands {
					if command.Kind == "Status" {
						continue
					}
					message.Commands = append(message.Commands, windows.SyncMLCommand{Kind: "Status", ID: strconv.Itoa(len(message.Commands) + 1), MessageRef: response.Header.MessageID, CommandRef: command.ID, CommandName: command.Kind, Data: &windows.SyncMLData{Text: outcome}})
					if command.Kind == "Get" {
						value := "  <script>device result</script>  "
						if command.Items[0].Target.URI == "./DevInfo/DevId" {
							value = "synthetic-csp-peer"
						}
						message.Commands = append(message.Commands, windows.SyncMLCommand{Kind: "Results", ID: strconv.Itoa(len(message.Commands) + 1), MessageRef: response.Header.MessageID, CommandRef: command.ID, Items: []windows.SyncMLItem{{Source: &windows.SyncMLLocation{URI: command.Items[0].Target.URI}, Meta: &windows.SyncMLMeta{Format: "chr"}, Data: &windows.SyncMLData{Text: value}}}})
					}
					acknowledge(command.Commands)
				}
			}
			acknowledge(response.Commands)
			return message
		}
		delivery := process(reply(process(initial), "200"))
		if status == "chunks" {
			// Twelve genuine correlated snapshots exercise history pagination.
			first := reply(delivery, "200")
			result := first.Commands[len(first.Commands)-1]
			if result.Kind != "Results" {
				t.Fatal("chunk fixture requires a Get")
			}
			value := "  <script>historical result</script>  "
			size := uint64(len(value))
			first.Final = false
			first.Commands[len(first.Commands)-1].Items = []windows.SyncMLItem{{Source: result.Items[0].Source, Meta: &windows.SyncMLMeta{Format: "chr", Size: &size}, Data: &windows.SyncMLData{Text: value[:2]}, MoreData: true}}
			response := process(first)
			for part := 1; part < 12; part++ {
				next := reply(response, "200")
				next.Final = part == 11
				end := (part + 1) * 2
				if next.Final {
					end = len(value)
				}
				chunk := result
				chunk.ID = strconv.Itoa(len(next.Commands) + 1)
				chunk.Items = []windows.SyncMLItem{{Source: result.Items[0].Source, Data: &windows.SyncMLData{Text: value[part*2 : end]}, MoreData: !next.Final}}
				next.Commands = append(next.Commands, chunk)
				response = process(next)
			}
		} else if status != "" {
			process(reply(delivery, status))
		}
		detail, err := h.Windows.CSPCommandDetails(ctx, "organization-admin", scope, deviceID, queued.ID)
		if err != nil {
			t.Fatal(err)
		}
		return detail
	}
	return deviceID, deliver, func() {
		t.Helper()
		rawNonce, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			t.Fatal(err)
		}
		inner := md5.Sum([]byte(deviceID + ":" + secret))
		outer := md5.Sum(append([]byte(base64.StdEncoding.EncodeToString(inner[:])+":"), rawNonce...))
		notification := &windows.SyncMLMessage{Header: windows.SyncMLHeader{SessionID: "1", MessageID: "1", Source: windows.SyncMLLocation{URI: "urn:uuid:synthetic-csp-console-peer", Name: deviceID}, Target: windows.SyncMLLocation{URI: h.WindowsOptions.ManagementURL}, Credential: &windows.SyncMLCredential{Digest: base64.StdEncoding.EncodeToString(outer[:])}}, Final: true, Commands: []windows.SyncMLCommand{{Kind: "Alert", ID: "1", Data: &windows.SyncMLData{Text: "1226"}, Items: []windows.SyncMLItem{{Meta: &windows.SyncMLMeta{Type: "com.microsoft:mdm.unenrollment.userrequest", Format: "int"}, Data: &windows.SyncMLData{Text: "1"}}}}}}
		response := process(notification)
		if len(response.Commands) != 2 || response.Commands[1].Data.Text != "200" {
			t.Fatal("synthetic disconnection was not acknowledged")
		}
	}
}
