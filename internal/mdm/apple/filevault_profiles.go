package apple

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
)

const fileVaultDomain = "eu.openuem.filevault"

var ErrFileVault = errors.New("FileVault management is unavailable")

func reservedFileVaultIdentifier(value string) bool {
	value = strings.ToLower(value)
	return value == fileVaultDomain || strings.HasPrefix(value, fileVaultDomain+".")
}

func fileVaultPayloadType(value string) bool {
	switch value {
	case "com.apple.security.FDERecoveryKeyEscrow", "com.apple.security.FDERecoveryRedirect", "com.apple.MCX.FileVault2", "com.apple.MCX":
		// MCX also controls FileVault recovery options. Treat it conservatively
		// as a conflict while the dedicated FileVault workflow owns the device.
		return true
	}
	return false
}

// FileVaultReason describes the evidence required before changing profiles.
// Enrollment and command acknowledgement alone do not prove disk encryption.
func (d Device) FileVaultReason(now time.Time) string {
	if d.Status != "enrolled" || d.Family() != PlatformMacOS {
		return "FileVault management requires an enrolled Mac."
	}
	if !d.Capabilities().Profiles || CompareVersions(d.OSVersion, "10.13") < 0 {
		return "FileVault recovery escrow requires macOS 10.13 or later."
	}
	if !d.InventoryFresh(now) || !d.SecurityFresh(now) {
		return "Refresh device and security inventory before managing FileVault."
	}
	management, _ := d.SecurityInventory["ManagementStatus"].(map[string]any)
	if enrolled, _ := management["IsUserEnrollment"].(bool); enrolled {
		return "FileVault management requires device enrollment."
	}
	if CompareVersions(d.OSVersion, "10.15") >= 0 {
		approved, _ := management["UserApprovedEnrollment"].(bool)
		if !approved && !(d.Supervised && d.SupervisedReported) {
			return "FileVault management requires user-approved enrollment or reported supervision."
		}
	}
	if !d.CertificateExpiresAt.After(now) {
		return "Renew the Mac management identity before managing FileVault."
	}
	return ""
}

func newFileVaultCertificate(id string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	serial, err := certificateSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "OpenUEM FileVault escrow " + id},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageKeyEncipherment, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, x509.MarshalPKCS1PrivateKey(key), nil
}

func fileVaultProfile(device, escrow, enable string, certificate []byte, activation bool) ([]byte, error) {
	for _, id := range []string{device, escrow, enable} {
		if _, err := uuid.Parse(id); err != nil {
			return nil, ErrFileVault
		}
	}
	identifier, rootID, name := fileVaultDomain+"."+device+".escrow", escrow, "OpenUEM FileVault recovery escrow"
	var payloads []any
	if activation {
		identifier, rootID, name = fileVaultDomain+"."+device+".enable", enable, "OpenUEM FileVault encryption"
		payloads = []any{map[string]any{
			"PayloadType": "com.apple.MCX.FileVault2", "PayloadVersion": 1,
			"PayloadIdentifier": identifier + ".settings", "PayloadUUID": uuid.NewString(),
			"Enable": "On", "Defer": true, "UseRecoveryKey": true, "ShowRecoveryKey": true,
			"DeferForceAtUserLoginMaxBypassAttempts": 3,
		}}
	} else {
		if _, err := x509.ParseCertificate(certificate); err != nil {
			return nil, ErrFileVault
		}
		certificateID := uuid.NewString()
		payloads = []any{
			map[string]any{
				"PayloadType": "com.apple.security.pkcs1", "PayloadVersion": 1,
				"PayloadIdentifier": identifier + ".certificate", "PayloadUUID": certificateID,
				"PayloadContent": certificate, "PayloadDisplayName": "FileVault recovery encryption certificate",
			},
			map[string]any{
				"PayloadType": "com.apple.security.FDERecoveryKeyEscrow", "PayloadVersion": 1,
				"PayloadIdentifier": identifier + ".destination", "PayloadUUID": uuid.NewString(),
				"EncryptCertPayloadUUID": certificateID, "DeviceKey": device,
				"Location": "Your organization's OpenUEM administrators can retrieve your recovery key.",
			},
		}
	}
	return plist.Marshal(map[string]any{
		"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System",
		"PayloadIdentifier": identifier, "PayloadUUID": rootID, "PayloadDisplayName": name,
		"PayloadContent": payloads,
	}, plist.XMLFormat)
}
