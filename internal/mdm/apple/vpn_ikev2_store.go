package apple

import (
	"context"
	"database/sql"
	"errors"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrVPNProfile = errors.New("invalid IKEv2 certificate profile")

type IKEv2CertificateOptions struct {
	Name, Identifier, Scope, ConnectionName                        string
	RemoteAddress, LocalIdentifier, RemoteIdentifier               string
	AuthenticationMode, CertificateType                            string
	ServerCertificateIssuerCommonName, ServerCertificateCommonName string
	Identity                                                       CertificateProfileReference
	Trust                                                          *CertificateProfileReference
}

func (s *Store) CreateIKEv2CertificateProfile(ctx context.Context, tenant int, o IKEv2CertificateOptions, actor string, permissions *access.Store) (*Profile, error) {
	return s.createIKEv2CertificateProfile(ctx, tenant, o, actor, func(ctx context.Context, tx *sql.Tx) error {
		if permissions == nil {
			return access.ErrDenied
		}
		return permissions.AuthorizeTransaction(ctx, tx, actor, access.ManageProfiles, access.Scope{TenantID: tenant})
	})
}

func (s *Store) createIKEv2CertificateProfile(ctx context.Context, tenant int, o IKEv2CertificateOptions, actor string, authorize func(context.Context, *sql.Tx) error) (*Profile, error) {
	settings := map[string]any{"UserDefinedName": o.ConnectionName, "RemoteAddress": o.RemoteAddress, "LocalIdentifier": o.LocalIdentifier, "RemoteIdentifier": o.RemoteIdentifier, "AuthenticationMode": o.AuthenticationMode, "CertificateType": o.CertificateType, "ServerCertificateIssuerCommonName": o.ServerCertificateIssuerCommonName, "ServerCertificateCommonName": o.ServerCertificateCommonName}
	return s.createCertificateNetworkProfile(ctx, tenant, certificateNetworkProfileOptions{Name: o.Name, Identifier: o.Identifier, Scope: o.Scope, Kind: "vpn-ikev2-certificate", Settings: settings, Identity: o.Identity, Trust: o.Trust}, actor, ErrVPNProfile, authorize)
}
