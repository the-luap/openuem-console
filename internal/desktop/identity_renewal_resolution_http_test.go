package desktop

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestPublicIdentityRenewalResolutionRecoversLostReplyThroughGateway(t *testing.T) {
	for _, gateway := range []bool{false, true} {
		for _, confirmed := range []bool{false, true} {
			t.Run(map[bool]string{false: "direct", true: "gateway"}[gateway]+"/"+map[bool]string{false: "cancelled", true: "confirmed"}[confirmed], func(t *testing.T) {
				f := newRenewalPublicFixture(t, gateway, true)
				target, confirmation := f.prepareConfirmation(t)
				var committedAt time.Time
				if confirmed {
					f.loseConfirmation.Store(true)
					if result, err := f.client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); !errors.Is(err, enrollment.ErrEnrollmentBusy) || result != nil {
						t.Fatal("lost confirmation unexpectedly returned evidence", err)
					}
					if err := f.store.db.QueryRow(`SELECT confirmed_at FROM uem_agent_identity_renewal_confirmations WHERE id=$1`, target.RequestID).Scan(&committedAt); err != nil {
						t.Fatal(err)
					}
				}
				var before string
				if err := f.store.db.QueryRow(`SELECT row_to_json(i)::text FROM uem_agent_identities i WHERE id=$1`, f.source.DeviceID).Scan(&before); err != nil {
					t.Fatal(err)
				}
				resolution, err := enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				f.loseResolution.Store(true)
				if result, err := f.client.ResolveIdentityRenewal(t.Context(), *resolution, *target, f.source); !errors.Is(err, enrollment.ErrEnrollmentBusy) || result != nil {
					t.Fatal("lost resolution granted generation selection", err)
				}
				// Reconstruct both SDK and registry after the committed reply was lost.
				f.client.CloseIdleConnections()
				client, err := enrollment.NewHTTPClient(f.source.Origin, f.roots)
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				restarted, err := registry.NewStore(f.store.db, "isolated-desktop-metadata-master-key")
				if err != nil {
					t.Fatal(err)
				}
				f.store.Registry = restarted
				resolution, err = enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				results := make(chan *enrollment.ResolvedIdentityRenewal, 3)
				failures := make(chan error, 3)
				for range 3 {
					wg.Go(func() {
						r, err := client.ResolveIdentityRenewal(t.Context(), *resolution, *target, f.source)
						if err != nil {
							failures <- err
						} else {
							results <- r
						}
					})
				}
				wg.Wait()
				close(results)
				close(failures)
				for err := range failures {
					t.Fatal(err)
				}
				var first *enrollment.ResolvedIdentityRenewal
				for r := range results {
					if first == nil {
						first = r
					} else if !reflect.DeepEqual(first, r) {
						t.Fatal("resolution retries changed original outcome")
					}
					if (r.Outcome == "confirmed") != confirmed || enrollment.ValidateResolvedIdentityRenewal(*r, *resolution, *target, f.source, time.Now()) != nil {
						t.Fatal("resolution selected wrong generation")
					}
					if confirmed && !r.ResolvedAt.Equal(committedAt) {
						t.Fatal("resolution changed original confirmation time")
					}
				}
				var after string
				if first == nil {
					t.Fatal("resolution produced no durable outcome")
				}
				if err := f.store.db.QueryRow(`SELECT row_to_json(i)::text FROM uem_agent_identities i WHERE id=$1`, f.source.DeviceID).Scan(&after); err != nil || before != after {
					t.Fatal("resolution mutated device identity", err)
				}
				var confirmations, cancellations, audits int
				if err := f.store.db.QueryRow(`SELECT (SELECT count(*) FROM uem_agent_identity_renewal_confirmations),(SELECT count(*) FROM uem_agent_identity_renewal_cancellations),(SELECT count(*) FROM uem_agent_audit WHERE action IN ('agent.identity.renew.cancel','agent.identity.renew.confirm'))`).Scan(&confirmations, &cancellations, &audits); err != nil || confirmations+cancellations != 1 || audits != 1 {
					t.Fatal("resolution duplicated generation transitions", err)
				}
				access, _ := registry.NewAccessStore(f.store.db)
				old, _ := x509.ParseCertificate(f.source.Certificate)
				candidate, _ := x509.ParseCertificate(target.Candidate.Certificate)
				_, oldErr := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, old)
				_, candidateErr := access.AuthenticateCertificate(t.Context(), f.source.DeviceID, candidate)
				if confirmed {
					if !errors.Is(oldErr, registry.ErrDenied) || candidateErr != nil {
						t.Fatal("resolved activation was not current")
					}
				} else {
					if oldErr != nil || !errors.Is(candidateErr, registry.ErrDenied) {
						t.Fatal("resolved cancellation changed credential authorization")
					}
					if _, err := client.ConfirmIdentityRenewal(t.Context(), *confirmation, *target); !errors.Is(err, enrollment.ErrIdentityRenewalDenied) {
						t.Fatal("late confirmation activated cancelled candidate", err)
					}
				}
			})
		}
	}
}

func TestPublicIdentityRenewalResolutionRejectsUnboundRequests(t *testing.T) {
	f := newRenewalPublicFixture(t, true, true)
	target, confirmation := f.prepareConfirmation(t)
	resolution, err := enrollment.NewRenewalResolution(*target, f.candidate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := json.Marshal(resolution)
	path := enrollment.IdentityRenewalPath(f.source.DeviceID, "resolve")
	for _, mode := range []string{"scope", "source", "candidate", "activation proof", "unknown request", "device", "origin", "duplicate", "null", "unknown field", "oversized", "media", "encoding", "authorization", "browser origin", "fetch site"} {
		request := *resolution
		headers := map[string]string{}
		status := 404
		switch mode {
		case "scope":
			request.SiteID++
		case "source":
			request.SourceCertificateHash = strings.Repeat("a", 64)
		case "candidate":
			request.CertificateHash = strings.Repeat("a", 64)
		case "activation proof":
			request.BrokerProof = confirmation.BrokerProof
		case "unknown request":
			request.RequestID = uuid.NewString()
		case "device":
			request.DeviceID = uuid.NewString()
			status = 400
		case "origin":
			request.Origin = "https://other.example.test"
			status = 400
		case "duplicate", "null", "unknown field":
			status = 400
		case "oversized":
			status = 413
		case "media":
			headers["Content-Type"] = "text/plain"
			status = 415
		case "encoding":
			headers["Content-Encoding"] = "gzip"
			status = 400
		case "authorization":
			headers["Authorization"] = "Bearer synthetic"
			status = 400
		case "browser origin":
			headers["Origin"] = "https://other.example.test"
			status = 403
		case "fetch site":
			headers["Sec-Fetch-Site"] = "cross-site"
			status = 403
		}
		body, _ := json.Marshal(request)
		switch mode {
		case "duplicate":
			body = append(valid[:len(valid)-1:len(valid)-1], []byte(`,"outcome":"cancelled","version":1}`)...)
		case "null":
			body = bytes.Replace(body, []byte(`"version":1`), []byte(`"version":null`), 1)
		case "unknown field":
			body = append(valid[:len(valid)-1:len(valid)-1], []byte(`,"fallback":true}`)...)
		case "oversized":
			body = bytes.Repeat([]byte("x"), enrollment.MaxRenewalResolutionBytes+1)
		}
		response, data := f.raw(t, "POST", path, body, headers)
		if response.StatusCode != status {
			t.Fatal("invalid resolution crossed public boundary", mode, response.StatusCode)
		}
		if bytes.Contains(data, []byte(request.RequestID)) || bytes.Contains(data, []byte(request.BrokerProof)) {
			t.Fatal("resolution error exposed request evidence")
		}
	}
	f.assertUnchanged(t, 1)
}
