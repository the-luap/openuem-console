package common

import (
	"errors"

	"github.com/open-uem/openuem-console/internal/desktop/consolebroker"
	"github.com/open-uem/openuem-console/internal/setup/administrator"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
	"github.com/open-uem/utils"
	"github.com/urfave/cli/v2"
)

func (w *Worker) GenerateConsoleConfigFromCLI(cCtx *cli.Context) error {
	var err error
	w.IndividualAgentService, err = consolebroker.FromEnvironment()
	if err != nil {
		return err
	}
	w.ProtectedAdministrator, err = administrator.FromEnvironment(w.IndividualAgentService != nil)
	if err != nil {
		return err
	}

	w.DBUrl = cCtx.String("dburl")

	w.CACertPath = cCtx.String("cacert")
	_, err = utils.ReadPEMCertificate(w.CACertPath)
	if err != nil {
		return err
	}

	w.ConsoleCertPath = cCtx.String("cert")
	_, err = utils.ReadPEMCertificate(w.ConsoleCertPath)
	if err != nil {
		return err
	}

	w.ConsolePrivateKeyPath = cCtx.String("key")
	_, err = utils.ReadPEMPrivateKey(w.ConsolePrivateKeyPath)
	if err != nil {
		return err
	}

	w.SFTPPrivateKeyPath = ""
	if w.IndividualAgentService != nil {
		w.NATSServers = w.IndividualAgentService.Servers
	} else {
		w.SFTPPrivateKeyPath = cCtx.String("sftpkey")
		_, err = utils.ReadPEMPrivateKey(w.SFTPPrivateKeyPath)
		if err != nil {
			return err
		}

		w.NATSServers = cCtx.String("nats-servers")

		if w.NATSServers == "" {
			return errors.New("legacy console requires NATS servers")
		}
	}

	credentials, err := secrets.Load(secrets.Inputs{JWT: cCtx.String("jwt-key"), Master: cCtx.String("encryption-master-key"), JWTFile: cCtx.String("jwt-key-file"), MasterFile: cCtx.String("encryption-master-key-file"), Required: w.IndividualAgentService != nil})
	if err != nil {
		return err
	}
	w.JWTKey, w.EncryptionMasterKey = credentials.JWT, credentials.Master

	w.ConsolePort = cCtx.String("console-port")
	w.AuthPort = cCtx.String("auth-port")
	w.ServerName = cCtx.String("server-name")
	w.Domain = cCtx.String("domain")
	w.OrgName = cCtx.String("org-name")
	w.OrgProvince = cCtx.String("org-province")
	w.OrgLocality = cCtx.String("org-locality")
	w.OrgAddress = cCtx.String("org-address")
	w.Country = cCtx.String("country")
	w.ReverseProxyAuthPort = cCtx.String("reverse-proxy-auth-port")
	w.ReverseProxyServer = cCtx.String("reverse-proxy-server")
	w.ReenableCertAuth = cCtx.Bool("re-enable-certificates-auth")
	w.ReenablePasswdAuth = cCtx.Bool("re-enable-passwd-auth")
	w.ResetOpenUEMUser = cCtx.Bool("reset-openuem-user")
	w.Version = "0.12.0"

	return w.validateAdministratorReset()
}
