package apple

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"

	"github.com/smallstep/scep"
)

func (s *Store) scepRenewalAuthority(ctx context.Context, deviceID, renewalID string, private bool) (*scepAuthority, error) {
	a := &scepAuthority{deviceID: deviceID, renewalID: renewalID}
	var caPEM, raDER []byte
	err := s.db.QueryRowContext(ctx, `SELECT r.authority_id,r.tenant_id,c.ca_certificate,a.certificate FROM mdm_apple_identity_renewals r JOIN mdm_apple_devices d ON d.id=r.device_id AND d.tenant_id=r.tenant_id JOIN mdm_apple_settings c ON c.tenant_id=r.tenant_id JOIN mdm_apple_scep_authorities a ON a.id=r.authority_id AND a.tenant_id=r.tenant_id JOIN mdm_apple_commands cmd ON cmd.id=r.command_id WHERE r.id=$1 AND r.device_id=$2 AND d.status='enrolled' AND d.certificate_fingerprint=r.base_fingerprint AND r.status IN ('queued','issued') AND r.expires_at>clock_timestamp() AND d.certificate_expires_at>clock_timestamp() AND cmd.status IN ('sent','not_now','acknowledged')`, renewalID, deviceID).Scan(&a.id, &a.tenant, &caPEM, &raDER)
	if err != nil {
		return nil, notFound(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, errSCEPAuthority
	}
	a.ca, a.ra, err = validateSCEPAuthority(block.Bytes, raDER, time.Now())
	if err != nil {
		return nil, err
	}
	if private {
		if err = s.loadSCEPAuthorityKey(ctx, a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (s *Store) scepRenew(ctx context.Context, a *scepAuthority, request *scepRequest) ([]byte, error) {
	fail := func() ([]byte, error) { return request.response(a.ra, a.key, a.ca, nil, scep.BadRequest) }
	if request.csr.Subject.CommonName != a.deviceID {
		return fail()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var active string
	if err = tx.QueryRowContext(ctx, `SELECT certificate_fingerprint FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND status='enrolled' AND certificate_expires_at>clock_timestamp() FOR UPDATE`, a.deviceID, a.tenant).Scan(&active); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fail()
		}
		return nil, err
	}
	var state, base, challenge, csrHash, signerFingerprint, transaction, commandState string
	var expires, baseExpires time.Time
	var certificate []byte
	err = tx.QueryRowContext(ctx, `SELECT r.status,r.base_fingerprint,COALESCE(r.challenge_hash,''),COALESCE(r.csr_hash,''),COALESCE(r.signer_fingerprint,''),COALESCE(r.transaction_id,''),r.certificate,r.expires_at,r.base_expires_at,c.status FROM mdm_apple_identity_renewals r JOIN mdm_apple_commands c ON c.id=r.command_id WHERE r.id=$1 AND r.device_id=$2 AND r.tenant_id=$3 AND r.authority_id=$4 FOR UPDATE OF r`, a.renewalID, a.deviceID, a.tenant, a.id).Scan(&state, &base, &challenge, &csrHash, &signerFingerprint, &transaction, &certificate, &expires, &baseExpires, &commandState)
	if errors.Is(err, sql.ErrNoRows) {
		return fail()
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if base != active || !now.Before(expires) || !now.Before(baseExpires) || !now.Before(a.ra.NotAfter) || !now.Before(a.ca.NotAfter) || (state != "queued" && state != "issued") || (commandState != "sent" && commandState != "not_now" && commandState != "acknowledged") {
		return fail()
	}
	var issued *x509.Certificate
	if state == "issued" {
		if csrHash != digest(request.csr.Raw) || signerFingerprint != digest(request.signer.Raw) || transaction != string(request.message.TransactionID) {
			return fail()
		}
		issued, err = x509.ParseCertificate(certificate)
		if err != nil || !now.Before(issued.NotAfter) {
			return nil, errSCEPAuthority
		}
	} else {
		switch request.message.MessageType {
		case scep.PKCSReq:
			if !validEnrollmentToken(request.challenge) || !hmac.Equal([]byte(challenge), []byte(digest([]byte(request.challenge)))) {
				return fail()
			}
		case scep.RenewalReq:
			// A CA chain alone never authorizes renewal. Pin the exact still-active
			// device signer, and require possession of the newly requested key too.
			if digest(request.signer.Raw) != active || bytes.Equal(request.csr.RawSubjectPublicKeyInfo, request.signer.RawSubjectPublicKeyInfo) {
				return fail()
			}
			if request.challenge != "" && !hmac.Equal([]byte(challenge), []byte(digest([]byte(request.challenge)))) {
				return fail()
			}
		default:
			return fail()
		}
		c := &Settings{TenantID: a.tenant}
		if err = tx.QueryRowContext(ctx, `SELECT organization,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1`, a.tenant).Scan(&c.Organization, &c.CACertificate, &c.CAKey); err != nil {
			return nil, err
		}
		c.CAKey, err = s.secrets.open(c.CAKey, secretPurpose(a.tenant, "settings", "ca_key"))
		if err != nil {
			return nil, errSCEPAuthority
		}
		ca, key, err := enrollmentCA(c, now)
		if err != nil || !bytes.Equal(ca.Raw, a.ca.Raw) {
			return nil, errSCEPAuthority
		}
		validUntil := now.AddDate(1, 0, 0)
		if ca.NotAfter.Before(validUntil) {
			validUntil = ca.NotAfter
		}
		if !baseExpires.Add(24 * time.Hour).Before(validUntil) {
			return nil, errSCEPAuthority
		}
		serial, err := certificateSerial()
		if err != nil {
			return nil, err
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: a.deviceID, Organization: []string{c.Organization}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: validUntil, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		certificate, err = x509.CreateCertificate(rand.Reader, template, ca, request.csr.PublicKey, key)
		if err != nil {
			return nil, err
		}
		issued, err = x509.ParseCertificate(certificate)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_identity_renewals SET status='issued',challenge_hash=NULL,csr_hash=$2,signer_fingerprint=$3,transaction_id=$4,certificate=$5,certificate_fingerprint=$6,certificate_expires_at=$7,issued_at=clock_timestamp() WHERE id=$1`, a.renewalID, digest(request.csr.Raw), digest(request.signer.Raw), string(request.message.TransactionID), certificate, digest(certificate), issued.NotAfter); err != nil {
			return nil, err
		}
		if err = audit(ctx, tx, a.tenant, "device:"+a.deviceID, "apple.identity.renewal.issue", a.renewalID); err != nil {
			return nil, err
		}
	}
	response, err := request.response(a.ra, a.key, a.ca, issued, "")
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return response, nil
}
