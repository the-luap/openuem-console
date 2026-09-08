package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/smallstep/scep"
	"howett.net/plist"
)

func TestIdentityRenewalPinsSignerAndBothKeyProofs(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	d, oldCert, oldKey := testEnrollWithKey(t, s, Scope{TenantID: 1, SiteID: 1}, "Renewal signer")
	drainCommands(t, s, d, nil)
	testIdentityDue(t, s, d)
	if err := s.ScheduleIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	r := testIdentityGeneration(t, s, d)
	profile := testIdentityDelivery(t, s, d, r)
	a, err := s.scepRenewalAuthority(ctx, d.ID, r.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	newKey, csr := testSCEPDeviceRequest(t, d.ID, "", a.ca, a.ra)
	active := &scepFixture{ca: a.ca, ra: a.ra, client: oldCert, clientKey: oldKey}
	for _, bad := range []struct {
		name string
		f    *scepFixture
		csr  *x509.CertificateRequest
		opts scepWireOptions
	}{
		{"unpinned signer", newKey, csr, scepWireOptions{kind: scep.RenewalReq}},
		{"missing initial challenge", newKey, csr, scepWireOptions{}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			request, err := parseSCEPRequest(testSCEPWire(t, bad.f, bad.csr, bad.opts), a.ra, a.key, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			response, err := s.scepRenew(ctx, a, request)
			if err != nil {
				t.Fatal(err)
			}
			testSCEPResult(t, bad.f, response, false)
		})
	}
	// Even the correct challenge cannot authorize the same request under another
	// device or generation, and a valid CA-issued signer is not an exact pin.
	wrong, wrongCSR := testSCEPDeviceRequest(t, d.ID, uuid.NewString(), a.ca, a.ra)
	request, err := parseSCEPRequest(testSCEPWire(t, wrong, wrongCSR, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.scepRenew(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, wrong, response, false)
	request, err = parseSCEPRequest(testSCEPWire(t, active, csr, scepWireOptions{kind: scep.RenewalReq}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"device", "generation", "tenant"} {
		other := *a
		switch change {
		case "device":
			other.deviceID = uuid.NewString()
		case "generation":
			other.renewalID = uuid.NewString()
		case "tenant":
			other.tenant = 2
		}
		response, err := s.scepRenew(ctx, &other, request)
		if err != nil {
			t.Fatal(err)
		}
		testSCEPResult(t, active, response, false)
	}
	response, err = s.scepRenew(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := scep.ParsePKIMessage(response, scep.WithCACerts([]*x509.Certificate{a.ca, a.ra}))
	if err != nil || parsed.PKIStatus != scep.SUCCESS {
		t.Fatal("pinned renewal rejected", err)
	}
	if err = parsed.DecryptPKIEnvelope(oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	if parsed.Certificate == nil || !bytes.Equal(parsed.Certificate.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) || bytes.Equal(parsed.Certificate.RawSubjectPublicKeyInfo, oldCert.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal did not certify the independently proven new key")
	}
	testIdentityPin(t, s, d, oldCert, "test-apns-token")
	// The consumed challenge cannot start a second request with another key.
	other, otherCSR := testSCEPDeviceRequest(t, d.ID, testSCEPProfile(t, profile)["Challenge"].(string), a.ca, a.ra)
	request, err = parseSCEPRequest(testSCEPWire(t, other, otherCSR, scepWireOptions{}), a.ra, a.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, err = s.scepRenew(ctx, a, request)
	if err != nil {
		t.Fatal(err)
	}
	testSCEPResult(t, other, response, false)
}

func TestIdentityRenewalPreservesEnrollmentFieldsAndSchedulesOnce(t *testing.T) {
	s := testStore(t)
	testSettings(t, s, 1)
	ctx := context.Background()
	d, _ := testEnroll(t, s, Scope{TenantID: 1, SiteID: 1}, "Profile replacement")
	drainCommands(t, s, d, nil)
	var old enrollmentLayout
	if err := s.db.QueryRow(`SELECT profile_uuid,mdm_uuid,identity_uuid,ca_uuid,public_url,topic,access_rights FROM mdm_apple_enrollment_layouts WHERE device_id=$1`, d.ID).Scan(&old.profileUUID, &old.mdmUUID, &old.identityUUID, &old.caUUID, &old.publicURL, &old.topic, &old.accessRights); err != nil {
		t.Fatal(err)
	}
	// Healthy certificates do not renew merely because maintenance ran.
	if err := s.ScheduleIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.IdentityRenewals(ctx, Scope{TenantID: 1}, d.ID)
	if err != nil || len(rows) != 0 {
		t.Fatal("renewal started outside the expiry window", err)
	}
	testIdentityDue(t, s, d)
	if err = s.ScheduleIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	r := testIdentityGeneration(t, s, d)
	profile := testIdentityDelivery(t, s, d, r)
	var root map[string]any
	if _, err = plist.Unmarshal(profile, &root); err != nil {
		t.Fatal(err)
	}
	payloads := root["PayloadContent"].([]any)
	ca, identity, mdm := payloads[0].(map[string]any), payloads[1].(map[string]any), payloads[2].(map[string]any)
	if root["PayloadUUID"] != old.profileUUID || root["PayloadIdentifier"] != "eu.openuem.enrollment."+d.ID || ca["PayloadUUID"] != old.caUUID || mdm["PayloadUUID"] != old.mdmUUID || mdm["Topic"] != old.topic || mdm["ServerURL"] != old.publicURL+"/mdm/apple/"+d.ID+"/connect" || mdm["CheckInURL"] != old.publicURL+"/mdm/apple/"+d.ID+"/checkin" || numberValue(mdm["AccessRights"]) != uint64(old.accessRights) || identity["PayloadUUID"] == old.identityUUID {
		t.Fatal("replacement changed immutable fields or reused identity payload")
	}
	testIdentityDue(t, s, d)
	if err = s.ScheduleIdentityRenewals(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = s.IdentityRenewals(ctx, Scope{TenantID: 1}, d.ID)
	if err != nil || len(rows) != 1 || rows[0].ID != r.ID {
		t.Fatal("maintenance created competing generations", err)
	}
	consoleDevice, err := s.Device(ctx, Scope{TenantID: 1}, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Connect(ctx, consoleDevice, map[string]any{"UDID": d.UDID, "Status": "Idle"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("console record substituted for certificate proof", err)
	}
}
