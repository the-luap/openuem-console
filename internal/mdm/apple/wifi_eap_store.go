package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"

	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

var ErrWiFiProfile = errors.New("invalid enterprise Wi-Fi profile")

type CertificateProfileReference struct {
	ProfileID string
	Revision  int
}

func ParseCertificateProfileReference(raw string) (CertificateProfileReference, error) {
	id, number, ok := strings.Cut(raw, "/")
	revision, err := strconv.Atoi(number)
	if !ok || err != nil || !profileRevisionUUID(id) || revision <= 0 || revision > 2147483647 || strconv.Itoa(revision) != number {
		return CertificateProfileReference{}, ErrWiFiProfile
	}
	return CertificateProfileReference{ProfileID: id, Revision: revision}, nil
}

type WiFiEAPTLSOptions struct {
	Name, Identifier, Scope, SSID, EncryptionType                string
	TLSMinimum, TLSMaximum, ServerNames, UserName, OuterIdentity string
	AutoJoin, Hidden                                             bool
	Identity                                                     CertificateProfileReference
	Trust                                                        *CertificateProfileReference
}

// The source revisions are immutable. A source update or catalog deletion after
// the operator selected a revision must never substitute different credentials.
func (s *Store) CreateWiFiEAPTLSProfile(ctx context.Context, tenant int, o WiFiEAPTLSOptions, actor string, permissions *access.Store) (*Profile, error) {
	return s.createWiFiEAPTLSProfile(ctx, tenant, o, actor, func(ctx context.Context, tx *sql.Tx) error {
		if permissions == nil {
			return access.ErrDenied
		}
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageProfiles, access.Scope{TenantID: tenant})
	})
}

func (s *Store) createWiFiEAPTLSProfile(ctx context.Context, tenant int, o WiFiEAPTLSOptions, actor string, authorize func(context.Context, *sql.Tx) error) (*Profile, error) {
	settings := map[string]any{"SSID_STR": o.SSID, "EncryptionType": o.EncryptionType, "TLSMinimumVersion": o.TLSMinimum, "TLSMaximumVersion": o.TLSMaximum, "ServerNameLines": o.ServerNames, "UserName": o.UserName, "OuterIdentity": o.OuterIdentity, "AutoJoin": o.AutoJoin, "HIDDEN_NETWORK": o.Hidden}
	return s.createCertificateNetworkProfile(ctx, tenant, certificateNetworkProfileOptions{Name: o.Name, Identifier: o.Identifier, Scope: o.Scope, Kind: "wifi-eap-tls", Settings: settings, Identity: o.Identity, Trust: o.Trust}, actor, ErrWiFiProfile, authorize)
}

type certificateNetworkProfileOptions struct {
	Name, Identifier, Scope, Kind string
	Settings                      map[string]any
	Identity                      CertificateProfileReference
	Trust                         *CertificateProfileReference
}

func (s *Store) createCertificateNetworkProfile(ctx context.Context, tenant int, o certificateNetworkProfileOptions, actor string, invalid error, authorize func(context.Context, *sql.Tx) error) (*Profile, error) {
	if tenant <= 0 || actor == "" || o.Scope != "System" && o.Scope != "User" || o.Settings == nil || o.Kind != "wifi-eap-tls" && o.Kind != "vpn-ikev2-certificate" {
		return nil, invalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return nil, err
		}
	}
	load := func(ref CertificateProfileReference) (*Profile, string, error) {
		if !profileRevisionUUID(ref.ProfileID) || ref.Revision <= 0 || ref.Revision > 2147483647 {
			return nil, "", invalid
		}
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profile_revisions WHERE tenant_id=$1 AND profile_id=$2 AND revision=$3`, tenant, ref.ProfileID, ref.Revision).Scan(&id); err != nil {
			return nil, "", notFound(err)
		}
		p, err := s.profileRevisionPayload(ctx, tx, tenant, id)
		return p, id, err
	}
	identity, identityRevision, err := load(o.Identity)
	if err != nil {
		return nil, err
	}
	defer clear(identity.Payload)
	settings := maps.Clone(o.Settings)
	settings["PayloadScope"], settings["IdentityProfileData"] = o.Scope, identity.Payload
	sources := []map[string]any{{"kind": "identity", "revision_id": identityRevision, "profile_id": identity.ID, "revision": identity.Revision}}
	description := "Identity configuration copied from " + identity.Name + " (revision " + strconv.Itoa(identity.Revision) + ")."
	if o.Trust != nil {
		trust, revision, err := load(*o.Trust)
		if err != nil {
			return nil, err
		}
		defer clear(trust.Payload)
		settings["TrustProfileData"] = trust.Payload
		sources = append(sources, map[string]any{"kind": "trust", "revision_id": revision, "profile_id": trust.ID, "revision": trust.Revision})
		description += " Trust certificates copied from " + trust.Name + " (revision " + strconv.Itoa(trust.Revision) + ")."
	}
	data, err := BuildProfile(o.Name, o.Identifier, o.Kind, settings)
	if err != nil {
		return nil, errors.Join(invalid, err)
	}
	var root map[string]any
	if _, err = plist.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	root["PayloadDescription"] = description + " Source changes do not update this copy."
	data, err = plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	p, err := ParseProfile(data)
	if err != nil {
		return nil, errors.Join(invalid, err)
	}
	p.TenantID = tenant
	if err = s.saveProfileRevisionTx(ctx, tx, p, false, actor, "", ""); err != nil {
		return nil, err
	}
	details, err := json.Marshal(map[string]any{"site_id": 0, "result": "success", "source_revisions": sources})
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_audit(tenant_id,actor,action,resource_id,details) VALUES($1,$2,'apple.profile.compose',$3,$4)`, tenant, actor, p.ID, details); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

// Selection uses catalog metadata only. Exact payload count and content are
// checked against the retained encrypted revision when the profile is created.
func IsIdentityCertificateProfile(p Profile) bool {
	if len(p.PayloadTypes) != 1 {
		return false
	}
	switch p.PayloadTypes[0] {
	case "com.apple.security.scep", "com.apple.security.acme", "com.apple.security.pkcs12", "com.apple.ADCertificate.managed":
		return true
	}
	return false
}

func IsPublicCertificateProfile(p Profile) bool {
	if len(p.PayloadTypes) == 0 {
		return false
	}
	for _, kind := range p.PayloadTypes {
		switch kind {
		case "com.apple.security.root", "com.apple.security.pem", "com.apple.security.pkcs1":
		default:
			return false
		}
	}
	return true
}
