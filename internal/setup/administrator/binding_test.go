package administrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func installationCredentials() secrets.Runtime {
	return secrets.Runtime{Installation: strings.Repeat("1", 32), JWT: strings.Repeat("j", 43), Master: strings.Repeat("m", 32)}
}

func TestInstallationSecretsDatabaseBinding(t *testing.T) {
	m := accountModel(t)
	ctx := context.Background()
	credentials := installationCredentials()
	// Legacy installations can start unbound; opting in requires a fresh registry.
	if err := secrets.CheckBinding(ctx, m.DB, secrets.Runtime{}); err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckBinding(ctx, m.DB, credentials); err != nil {
		t.Fatal(err)
	}
	var storedID string
	var jwtProof, masterProof []byte
	if err := m.DB.QueryRow(`SELECT installation,jwt_proof,master_proof FROM uem_installation_secrets`).Scan(&storedID, &jwtProof, &masterProof); err != nil {
		t.Fatal(err)
	}
	if storedID != credentials.Installation || len(jwtProof) != 32 || len(masterProof) != 32 || string(jwtProof) == credentials.JWT || string(masterProof) == credentials.Master {
		t.Fatal("binding persisted unexpected credential material")
	}
	config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, testPassword)}
	if created, err := Initialize(ctx, m.DB, config); err != nil || !created {
		t.Fatal("bound initialization failed", err)
	}
	original, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckBinding(ctx, m.DB, credentials); err != nil {
		t.Fatal("same-key restart failed", err)
	}
	for _, kind := range []string{"missing ID", "different ID", "missing JWT", "changed JWT", "changed master", "missing master"} {
		t.Run(kind, func(t *testing.T) {
			changed := credentials
			switch kind {
			case "missing ID":
				changed.Installation = ""
			case "different ID":
				changed.Installation = strings.Repeat("2", 32)
			case "missing JWT":
				changed.JWT = ""
			case "changed JWT":
				changed.JWT = strings.Repeat("k", 43)
			case "changed master":
				changed.Master = strings.Repeat("n", 32)
			case "missing master":
				changed.Master = ""
			}
			if err := secrets.CheckBinding(ctx, m.DB, changed); !errors.Is(err, secrets.ErrBinding) {
				t.Fatal("changed/omitted credentials were accepted", err)
			}
		})
	}
	current, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil || current.Hash != original.Hash || current.Register != original.Register {
		t.Fatal("binding check changed the account", err)
	}
	// A marker is independent of the row and cannot be bypassed by clearing env.
	if _, err := m.DB.Exec(`DELETE FROM uem_installation_secrets`); err != nil {
		t.Fatal(err)
	}
	for _, value := range []secrets.Runtime{credentials, {}} {
		if err := secrets.CheckBinding(ctx, m.DB, value); !errors.Is(err, secrets.ErrBinding) {
			t.Fatal("missing binding was silently repaired", err)
		}
	}
	if _, err := m.DB.Exec(`DELETE FROM uem_access_grants; DELETE FROM users`); err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckBinding(ctx, m.DB, credentials); !errors.Is(err, secrets.ErrBinding) {
		t.Fatal("deleted accounts permitted binding reset", err)
	}
}

func TestInstallationSecretsBindingTransactionAndAdoption(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"rollback", "legacy", "missing marker"} {
		t.Run(kind, func(t *testing.T) {
			m := accountModel(t)
			credentials := installationCredentials()
			if err := secrets.CheckBinding(ctx, m.DB, secrets.Runtime{}); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "rollback":
				if _, err := m.DB.Exec(`CREATE FUNCTION reject_secret_marker() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.name='installation-secrets' THEN RAISE EXCEPTION 'synthetic marker failure'; END IF; RETURN NEW; END $$;
				CREATE TRIGGER reject_secret_marker BEFORE INSERT ON uem_access_migrations FOR EACH ROW EXECUTE FUNCTION reject_secret_marker()`); err != nil {
					t.Fatal(err)
				}
				if err := secrets.CheckBinding(ctx, m.DB, credentials); !errors.Is(err, secrets.ErrBinding) {
					t.Fatal("marker failure did not roll back", err)
				}
				var count int
				if err := m.DB.QueryRow(`SELECT count(*) FROM uem_installation_secrets`).Scan(&count); err != nil || count != 0 {
					t.Fatal("failed binding left a credential row", err)
				}
				if _, err := m.DB.Exec(`DROP TRIGGER reject_secret_marker ON uem_access_migrations`); err != nil {
					t.Fatal(err)
				}
				if err := secrets.CheckBinding(ctx, m.DB, credentials); err != nil {
					t.Fatal("exact retry failed", err)
				}
			case "legacy":
				config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, testPassword)}
				if _, err := Initialize(ctx, m.DB, config); err != nil {
					t.Fatal(err)
				}
				if err := secrets.CheckBinding(ctx, m.DB, credentials); !errors.Is(err, secrets.ErrBinding) {
					t.Fatal("occupied legacy registry was silently adopted", err)
				}
				if err := secrets.CheckBinding(ctx, m.DB, secrets.Runtime{}); err != nil {
					t.Fatal("unbound legacy restart failed", err)
				}
			case "missing marker":
				if err := secrets.CheckBinding(ctx, m.DB, credentials); err != nil {
					t.Fatal(err)
				}
				if _, err := m.DB.Exec(`DELETE FROM uem_access_migrations WHERE name='installation-secrets'`); err != nil {
					t.Fatal(err)
				}
				if err := secrets.CheckBinding(ctx, m.DB, credentials); !errors.Is(err, secrets.ErrBinding) {
					t.Fatal("missing marker accepted", err)
				}
			}
		})
	}
}

func TestInstallationSecretsCompetingDatabaseBindings(t *testing.T) {
	m := accountModel(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	winners := make(chan secrets.Runtime, 6)
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value := installationCredentials()
			value.Installation = fmt.Sprintf("%032x", i+1)
			if err := secrets.CheckBinding(ctx, m.DB, value); err == nil {
				winners <- value
			} else if !errors.Is(err, secrets.ErrBinding) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(winners)
	var count int
	for winner := range winners {
		count++
		if err := secrets.CheckBinding(ctx, m.DB, winner); err != nil {
			t.Fatal("committed binding was lost", err)
		}
	}
	if count != 1 {
		t.Fatal("competing installations did not have exactly one winner", count)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := secrets.CheckBinding(cancelled, m.DB, installationCredentials()); !errors.Is(err, secrets.ErrBinding) {
		t.Fatal("cancelled check was accepted", err)
	}
}
