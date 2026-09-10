package apple

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestFileVaultRotationAcknowledgementFailureRollsBackRetainedKeyAndFinalAudit(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	task := queueFileVaultRotation(t, f)
	newKey := []byte("1111-2222-3333-4444-5555-6666")
	reportFileVaultRotation(t, f, task, "rotated", newKey)
	if _, err := f.s.db.Exec(`CREATE FUNCTION reject_rotation_reconciliation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='recovery.rotation.reconciled' THEN RAISE EXCEPTION 'synthetic reconciliation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_rotation_reconciliation_audit BEFORE INSERT ON uem_agent_audit FOR EACH ROW EXECUTE FUNCTION reject_rotation_reconciliation_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err == nil {
		t.Fatal("reconciliation ignored registry audit failure")
	}
	var intact bool
	if err := f.s.db.QueryRow(`SELECT r.status='queued' AND r.candidate_key_id IS NULL AND octet_length(r.reply_private)>0 AND p.current_key_id=$2 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=1 AND NOT EXISTS(SELECT 1 FROM mdm_apple_audit WHERE action='apple.filevault.rotation.rotated' AND resource_id=($1::uuid)::text) FROM mdm_apple_filevault_rotations r JOIN mdm_apple_filevault_policies p ON p.device_id=r.device_id WHERE r.id=$1`, task.Context.Binding.TaskID, f.keyID).Scan(&intact); err != nil || !intact {
		t.Fatal("failed acknowledgement partly committed key processing", err)
	}
	rotationReconciliationState(t, f, task.Context.Binding.TaskID, false)
	if _, err := f.s.db.Exec(`DROP TRIGGER reject_rotation_reconciliation_audit ON uem_agent_audit`); err != nil {
		t.Fatal(err)
	}
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
		t.Fatal("key processing could not retry after rollback", err)
	}
	rotationReconciliationState(t, f, task.Context.Binding.TaskID, true)
	var candidate string
	if err := f.s.db.QueryRow(`SELECT candidate_key_id FROM mdm_apple_filevault_rotations WHERE id=$1`, task.Context.Binding.TaskID).Scan(&candidate); err != nil {
		t.Fatal(err)
	}
	plain, err := f.s.revealFileVaultKey(t.Context(), f.scope, f.d.ID, candidate, "admin", nil)
	if err != nil || !bytes.Equal(plain, newKey) {
		t.Fatal("acknowledged key was not durably retained", err)
	}
	clear(plain)
}

// Only this synthetic fixture reissues its own certificate to enter the renewal
// window without sleeping. The original fixture CA/key and registry master key
// remain unchanged; changing only expiry metadata would not be a valid fixture.
func shortenRotationFixtureIdentity(t *testing.T, f *validationFixture) {
	t.Helper()
	var authority, encrypted []byte
	if err := f.s.db.QueryRow(`SELECT certificate,encrypted_key FROM uem_agent_authorities WHERE tenant_id=1`).Scan(&authority, &encrypted); err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("openuem/agent-registry/secrets/v1\x00integration-test-master-key-32-bytes-minimum"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) < aead.NonceSize() {
		t.Fatal("invalid fixture CA key")
	}
	private, err := aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], []byte("1/authority/key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	caBlock, _ := pem.Decode(authority)
	keyBlock, _ := pem.Decode(private)
	if caBlock == nil || keyBlock == nil {
		t.Fatal("invalid fixture issuer encoding")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	clear(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		t.Fatal("fixture issuer cannot sign")
	}
	leaf := *f.cert
	leaf.SerialNumber = big.NewInt(42)
	leaf.NotAfter = time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &leaf, ca, &f.keys.Certificate.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	f.cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`UPDATE uem_agent_identities SET certificate=$2,certificate_hash=$3,certificate_expires_at=$4 WHERE id=$1`, f.identity.ID, der, digest(der), leaf.NotAfter); err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.access.ActiveIdentity(t.Context(), f.identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.register(t, f.private)
}

func TestFileVaultReturnedKeySurvivesConfirmedDesktopIdentityRenewal(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	shortenRotationFixtureIdentity(t, f)
	task := queueFileVaultRotation(t, f)
	newKey := []byte("1111-2222-3333-4444-5555-6666")
	reportFileVaultRotation(t, f, task, "rotated", newKey)
	candidate, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Broker.Wipe)
	broker, _ := f.keys.Broker.PublicKey()
	source := enrollment.RenewalSource{DeviceID: f.identity.ID, TenantID: 1, SiteID: 1, Origin: "https://uem.example.test", Platform: "macos", Architecture: "arm64", BrokerKey: broker, Certificate: f.cert.Raw}
	request, err := enrollment.NewRenewalRequest(source, f.keys, candidate, uuid.NewString(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.registry.PrepareIdentityRenewal(t.Context(), *request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := enrollment.ValidateResponse(prepared.Response, source.Origin, &candidate.Certificate.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	target := enrollment.RenewalConfirmationTarget{RequestID: prepared.ID, SourceCertificateHash: prepared.SourceCertificateHash, Candidate: source}
	target.Candidate.Certificate = issued.Raw
	target.Candidate.BrokerKey, _ = candidate.Broker.PublicKey()
	confirm, err := enrollment.NewRenewalConfirmation(target, candidate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.ConfirmIdentityRenewal(t.Context(), *confirm); !errors.Is(err, registry.ErrRenewalRecoveryPending) {
		t.Fatal("unprocessed returned key allowed certificate handoff", err)
	}
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	rotationReconciliationState(t, f, task.Context.Binding.TaskID, true)
	var keyID string
	var receipt []byte
	if err := f.s.db.QueryRow(`SELECT r.candidate_key_id,t.result FROM mdm_apple_filevault_rotations r JOIN uem_agent_rotation_tasks t ON t.id=r.id WHERE r.id=$1`, task.Context.Binding.TaskID).Scan(&keyID, &receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.ConfirmIdentityRenewal(t.Context(), *confirm); err != nil {
		t.Fatal("processed key did not release renewal", err)
	}
	if _, err := f.access.AuthenticateCertificate(t.Context(), source.DeviceID, f.cert); !errors.Is(err, registry.ErrDenied) {
		t.Fatal("retired desktop certificate accepted", err)
	}
	if _, err := f.access.AuthenticateCertificate(t.Context(), source.DeviceID, issued); err != nil {
		t.Fatal("replacement desktop certificate rejected", err)
	}
	var retained []byte
	if err := f.s.db.QueryRow(`SELECT result FROM uem_agent_rotation_tasks WHERE id=$1`, task.Context.Binding.TaskID).Scan(&retained); err != nil || !bytes.Equal(receipt, retained) {
		t.Fatal("renewal changed original rotation evidence", err)
	}
	plain, err := f.s.revealFileVaultKey(t.Context(), f.scope, f.d.ID, keyID, "admin", nil)
	if err != nil || !bytes.Equal(plain, newKey) {
		t.Fatal("renewal lost returned recovery key", err)
	}
	clear(plain)
	previousEpoch := f.recipient.ID
	f.keys, f.cert = candidate, issued
	f.identity, err = f.access.ActiveIdentity(t.Context(), source.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	f.register(t, f.private)
	if f.recipient.ID == previousEpoch || f.recipient.Identity.CertificateHash != confirm.CertificateHash {
		t.Fatal("renewed identity reused retired recovery epoch")
	}
}

func TestFileVaultRotationRequiresRegistryReconciliationMigration(t *testing.T) {
	f := newFileVaultRotationFixture(t)
	task := queueFileVaultRotation(t, f)
	reportFileVaultRotation(t, f, task, "rotated", []byte("1111-2222-3333-4444-5555-6666"))
	// Only the disposable fixture removes this table to reproduce an older
	// registry during an upgrade. Existing return keys must remain recoverable.
	if _, err := f.s.db.Exec(`DROP TABLE uem_agent_rotation_reconciliations; DELETE FROM uem_agent_migrations WHERE name='migrations/009_rotation_reconciliations.sql'`); err != nil {
		t.Fatal(err)
	}
	if rotationSchemaReady(t.Context(), f.s.db) {
		t.Fatal("old registry advertised complete rotation support")
	}
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err == nil {
		t.Fatal("key processing ignored missing acknowledgement storage")
	}
	var preserved bool
	if err := f.s.db.QueryRow(`SELECT status='queued' AND octet_length(reply_private)>0 AND (SELECT count(*) FROM mdm_apple_filevault_keys)=1 FROM mdm_apple_filevault_rotations WHERE id=$1`, task.Context.Binding.TaskID).Scan(&preserved); err != nil || !preserved {
		t.Fatal("partial registry upgrade lost returned key", err)
	}
	if err := f.registry.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !rotationSchemaReady(t.Context(), f.s.db) {
		t.Fatal("registry upgrade did not restore rotation readiness")
	}
	if err := f.s.checkFileVaultRotation(t.Context(), f.scope, f.d.ID, task.Context.Binding.TaskID); err != nil {
		t.Fatal(err)
	}
	rotationReconciliationState(t, f, task.Context.Binding.TaskID, true)
}
