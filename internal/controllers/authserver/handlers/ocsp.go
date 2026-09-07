package handlers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

func checkRevocation(ctx context.Context, cert, issuer *x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		return errors.New("certificate has no revocation responder")
	}
	target, err := url.Parse(cert.OCSPServer[0])
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Fragment != "" {
		return errors.New("invalid revocation responder")
	}
	payload, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("revocation responder unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errors.New("revocation response exceeds limit")
	}
	return verifyRevocationResponse(data, cert, issuer, time.Now())
}

func verifyRevocationResponse(data []byte, cert, issuer *x509.Certificate, now time.Time) error {
	response, err := ocsp.ParseResponseForCert(data, cert, issuer)
	if err != nil {
		return err
	}
	if response.Status != ocsp.Good {
		return errors.New("certificate is revoked or its status is unknown")
	}
	if response.ThisUpdate.IsZero() || response.ThisUpdate.After(now.Add(5*time.Minute)) || now.Sub(response.ThisUpdate) > 24*time.Hour || (!response.NextUpdate.IsZero() && (!now.Before(response.NextUpdate) || !response.NextUpdate.After(response.ThisUpdate))) {
		return errors.New("revocation response is stale or not yet valid")
	}
	return nil
}
