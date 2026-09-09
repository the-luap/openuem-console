package apple

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/ade"
	"howett.net/plist"
)

func adeArmedFixture(t *testing.T) (*Store, string, *adeEnrollmentFixture, ADEEnrollmentProfile, string, *ade.MachineInfo) {
	t.Helper()
	s, server, f := adeEnrollmentStore(t)
	p := adeProfilePublished(t, s, server)
	info := &ade.MachineInfo{Serial: "SYNTHETICMAC1", UDID: uuid.NewString(), Product: "Mac14,7", OSVersion: "15.6", Build: "24G100", SignerFingerprint: strings.Repeat("a", 64), SignedAt: time.Now()}
	adeAddSerial(t, s, f, server, info.Serial)
	if err := s.setADETargets(t.Context(), 1, server, p.ID, []string{info.Serial}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileADETargetBatch(t.Context(), 1, server); err != nil {
		t.Fatal(err)
	}
	definition := f.profiles[p.RemoteID]
	selector := definition.URL[strings.LastIndex(definition.URL, "/")+1:]
	return s, server, f, p, selector, info
}

func adeAdmittedDevice(t *testing.T, s *Store, serial string) *Device {
	t.Helper()
	var id string
	if err := s.db.QueryRow(`SELECT device_id FROM mdm_apple_ade_admissions WHERE serial=$1 ORDER BY generation DESC LIMIT 1`, serial).Scan(&id); err != nil {
		t.Fatal(err)
	}
	d, err := s.Device(t.Context(), Scope{TenantID: 1, SiteID: 1}, id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func adeAuthenticate(t *testing.T, s *Store, info *ade.MachineInfo, profile []byte, awaiting bool) (*Device, *x509.Certificate) {
	t.Helper()
	d := adeAdmittedDevice(t, s, info.Serial)
	if d.UDID != "" || d.Status != "authenticating" || d.EnrollmentMethod != "automated_device" {
		t.Fatal("admission bypassed device authentication")
	}
	_, cert := testSCEPEnrollProfile(t, s, d.ID, profile)
	d, err := s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]any{"MessageType": "Authenticate", "Topic": "com.apple.mgmt.test", "UDID": info.UDID, "SerialNumber": info.Serial, "ProductName": info.Product, "OSVersion": info.OSVersion}
	for _, field := range []string{"UDID", "SerialNumber"} {
		original := auth[field]
		auth[field] = "WRONG"
		if err = s.CheckIn(t.Context(), d, auth); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("signed identity was replaced", field, err)
		}
		auth[field] = original
	}
	if err = s.CheckIn(t.Context(), d, auth); err != nil {
		t.Fatal(err)
	}
	d, err = s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "TokenUpdate", "Topic": "com.apple.mgmt.test", "UDID": info.UDID, "Token": []byte("synthetic-apns-token"), "PushMagic": "synthetic-magic", "AwaitingConfiguration": awaiting}); err != nil {
		t.Fatal(err)
	}
	d, err = s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	return d, cert
}

func TestADEAdmissionConcurrentRetryIdentityAndRearm(t *testing.T) {
	s, server, _, _, selector, info := adeArmedFixture(t)
	var profiles [3][]byte
	var errs [3]error
	var wg sync.WaitGroup
	for i := range profiles {
		wg.Go(func() { profiles[i], errs[i] = s.admitADE(t.Context(), selector, info) })
	}
	wg.Wait()
	for i := range profiles {
		if errs[i] != nil || !bytes.Equal(profiles[0], profiles[i]) {
			t.Fatal("concurrent retry created a different profile", errs[i])
		}
	}
	var root map[string]any
	if _, err := plist.Unmarshal(profiles[0], &root); err != nil || root["PayloadRemovalDisallowed"] != true {
		t.Fatal("nonremovable ADE enrollment was lost", err)
	}
	d := adeAdmittedDevice(t, s, info.Serial)
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM mdm_apple_ade_admissions`).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate admission", count, err)
	}
	var expires time.Time
	if err := s.db.QueryRow(`SELECT expires_at FROM mdm_apple_ade_admissions WHERE device_id=$1`, d.ID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	wrong := *info
	wrong.SignerFingerprint = strings.Repeat("b", 64)
	if _, err := s.admitADE(t.Context(), selector, &wrong); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retry changed signer", err)
	}
	if err := s.rearmADETarget(t.Context(), 1, server, info.Serial, "admin", nil); err == nil {
		t.Fatal("active enrollment was rearmed")
	}
	d, cert := adeAuthenticate(t, s, info, profiles[0], true)
	if _, err := s.admitADE(t.Context(), selector, info); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("enrolled device reused admission", err)
	}
	var deadline time.Time
	var retry []byte
	if err := s.db.QueryRow(`SELECT expires_at,retry_profile FROM mdm_apple_ade_admissions WHERE device_id=$1`, d.ID).Scan(&deadline, &retry); err != nil || !deadline.Equal(expires) || len(retry) != 0 {
		t.Fatal("retry credential retained or extended", err)
	}
	if err := s.RevokeEnrollment(t.Context(), Scope{TenantID: 1, SiteID: 1}, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	state, err := s.ADEDeviceEnrollment(t.Context(), Scope{TenantID: 1}, d.ID)
	if err != nil || state.SetupState != "cancelled" {
		t.Fatal("revocation left an active setup", err)
	}
	if err = s.rearmADETarget(t.Context(), 1, server, info.Serial, "admin", nil); err != nil {
		t.Fatal(err)
	}
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil || bytes.Equal(profile, profiles[0]) {
		t.Fatal("rearmed activation did not create a new identity", err)
	}
	if _, err = s.AuthenticateCertificate(t.Context(), d.ID, cert); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("prior identity revived", err)
	}
}

func TestADEAdmissionRequiresCurrentAppleProof(t *testing.T) {
	s, server, f, p, selector, info := adeArmedFixture(t)
	original := f.details[info.Serial]
	for _, change := range []func(*ade.DeviceDetail){
		func(d *ade.DeviceDetail) { d.ResponseStatus = "NOT_ACCESSIBLE" },
		func(d *ade.DeviceDetail) { d.ProfileID = "FOREIGN" },
		func(d *ade.DeviceDetail) { d.ProfileStatus = "removed" },
	} {
		d := original
		change(&d)
		f.details[info.Serial] = d
		if _, err := s.admitADE(t.Context(), selector, info); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("unproven Apple assignment admitted", err)
		}
	}
	delete(f.details, info.Serial)
	if _, err := s.admitADE(t.Context(), selector, info); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("omitted device admitted", err)
	}
	f.details[info.Serial] = original
	definition := f.profiles[p.RemoteID]
	changed := definition
	changed.Removable = true
	f.profiles[p.RemoteID] = changed
	if _, err := s.admitADE(t.Context(), selector, info); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("modified remote profile admitted", err)
	}
	f.profiles[p.RemoteID] = definition
	for _, signed := range []time.Time{time.Now().Add(-2 * time.Hour), time.Now().Add(time.Hour)} {
		wrong := *info
		wrong.SignedAt = signed
		if _, err := s.admitADE(t.Context(), selector, &wrong); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("stale or future signed request admitted", err)
		}
	}
	wrong := *info
	wrong.Product = "iPhone16,1"
	if _, err := s.admitADE(t.Context(), selector, &wrong); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("profile admitted another platform", err)
	}
	// Optional signingTime is not an invented mandatory nonce.
	info.SignedAt = time.Time{}
	profile, err := s.admitADE(t.Context(), selector, info)
	if err != nil {
		t.Fatal(err)
	}
	d := adeAdmittedDevice(t, s, info.Serial)
	_, cert := testSCEPEnrollProfile(t, s, d.ID, profile)
	d, err = s.AuthenticateCertificate(t.Context(), d.ID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.setADETargets(t.Context(), 1, server, "", []string{info.Serial}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckIn(t.Context(), d, map[string]any{"MessageType": "Authenticate", "Topic": "com.apple.mgmt.test", "UDID": info.UDID, "SerialNumber": info.Serial}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("disarmed initial identity authenticated", err)
	}
}

func TestADEPublicAdmissionHTTPBoundary(t *testing.T) {
	s, _, _, _, selector, info := adeArmedFixture(t)
	h := s.ProtocolHandler(nil)
	request := func(method, suffix, body string, secure bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://mdm.example.test/mdm/apple/ade/"+selector+suffix, strings.NewReader(body))
		if secure {
			r.TLS = &tls.ConnectionState{HandshakeComplete: true}
		} else {
			r.TLS = nil
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("POST", "", "unsigned", true); w.Code != 403 {
		t.Fatal("production verifier accepted unsigned input", w.Code)
	}
	calls := 0
	s.verifyADEMachineInfo = func(body []byte) (*ade.MachineInfo, error) {
		calls++
		if string(body) != "synthetic signed device statement" {
			return nil, errors.New("synthetic signature failure")
		}
		return info, nil
	}
	for _, tc := range []struct {
		method, suffix string
		secure         bool
		status         int
	}{
		{"POST", "", false, 400}, {"GET", "", true, 405}, {"POST", "?x=1", true, 404}, {"POST", "?", true, 404}, {"POST", "/extra", true, 404},
	} {
		if w := request(tc.method, tc.suffix, "synthetic signed device statement", tc.secure); w.Code != tc.status {
			t.Fatal("invalid public route accepted", tc, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("invalid route invoked signature verification")
	}
	if w := request("POST", "", strings.Repeat("x", ade.MaxMachineInfo+1), true); w.Code != 413 || calls != 0 {
		t.Fatal("oversized signature parsed", w.Code)
	}
	w := request("POST", "", "synthetic signed device statement", true)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatal("profile response failed", w.Code)
	}
	retry := request("POST", "", "synthetic signed device statement", true)
	if retry.Code != 200 || !bytes.Equal(w.Body.Bytes(), retry.Body.Bytes()) {
		t.Fatal("HTTP retry changed profile", retry.Code)
	}
}

func TestADEAdmissionAuditFailureRollsBackIdentity(t *testing.T) {
	s, _, _, _, selector, info := adeArmedFixture(t)
	adeExec(t, s, `CREATE FUNCTION fail_ade_admission_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.enrollment.ade.admit' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`)
	adeExec(t, s, `CREATE TRIGGER fail_ade_admission_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION fail_ade_admission_audit()`)
	if _, err := s.admitADE(t.Context(), selector, info); err == nil {
		t.Fatal("unaudited admission succeeded")
	}
	var id string
	if err := s.db.QueryRow(`SELECT device_id FROM mdm_apple_ade_admissions`).Scan(&id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("failed audit retained identity", err)
	}
	adeExec(t, s, `DROP TRIGGER fail_ade_admission_audit ON mdm_apple_audit`)
	if _, err := s.admitADE(t.Context(), selector, info); err != nil {
		t.Fatal("rolled back admission could not retry", err)
	}
}
