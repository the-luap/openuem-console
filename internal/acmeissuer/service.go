//go:build linux || darwin

package acmeissuer

import (
	"context"
	"errors"
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type Result struct {
	Version     int         `json:"version"`
	AttemptedAt time.Time   `json:"attempted_at"`
	Phase       string      `json:"phase"`
	Published   bool        `json:"published"`
	Generation  *Generation `json:"generation,omitempty"`
}

type Service struct {
	config             Config
	binary             string
	state, publication *directory
	installationID     string
	runner             func(context.Context, string, string, []string, []string) error
	mu                 sync.Mutex
	lifetime           sync.RWMutex
	closed             bool
}

func Open(config Config, binary string) (*Service, error) {
	if err := config.CheckInputs(binary); err != nil {
		return nil, err
	}
	config.Resolvers = append([]string(nil), config.Resolvers...)
	service := &Service{config: config, binary: binary, runner: runLego}
	var err error
	service.state, err = openDirectory(config.StateDirectory)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			service.Close()
		}
	}()
	service.publication, err = openDirectory(config.PublicationDirectory)
	if err != nil {
		return nil, err
	}
	service.installationID, err = bindInstallation(service.state, service.publication, config)
	if err != nil {
		return nil, ErrState
	}
	current, err := service.publication.current(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if service.state.account(config, current != nil, current != nil, false) != nil {
		return nil, ErrState
	}
	if err := service.state.root.MkdirAll("lego", 0700); err != nil {
		return nil, ErrState
	}
	if syncRoot(service.state.root) != nil {
		return nil, ErrState
	}
	ready = true
	return service, nil
}

// Close is called after Run/Once has returned and joined the issuer invocation.
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lifetime.Lock()
	defer s.lifetime.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.publication != nil {
		s.publication.close()
	}
	if s.state != nil {
		s.state.close()
	}
}

func (s *Service) arguments() []string {
	c := s.config
	args := []string{"--log.level", "error", "--log.format", "json", "run",
		"--accept-tos", "--server", c.DirectoryURL, "--email", c.Email,
		"--dns", c.Provider, "--domains", c.domain(), "--cert.name", "gateway",
		"--path", filepath.Join(c.StateDirectory, "lego"), "--key-type", "EC256",
		"--force-cert-domains", "--tls-skip-verify=false", "--http-timeout", "30",
		"--cert.timeout", "60", "--dns.timeout", "10", "--no-random-sleep"}
	for _, resolver := range c.Resolvers {
		args = append(args, "--dns.resolvers", resolver)
	}
	if c.Profile != "" {
		args = append(args, "--profile", c.Profile)
	}
	return args
}

func (s *Service) Once(ctx context.Context) (result Result, err error) {
	result = Result{Version: 1, AttemptedAt: time.Now().UTC(), Phase: "configuration"}
	if !s.mu.TryLock() {
		return result, ErrLocked
	}
	defer s.mu.Unlock()
	if s.closed {
		return result, ErrState
	}
	defer func() {
		// This status has no account identifier, provider output or credential.
		if s.state.writeJSON("status.json", result) != nil && err == nil {
			err = ErrState
		}
	}()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if s.state.unchanged() != nil || s.publication.unchanged() != nil {
		return result, ErrState
	}
	current, err := s.publication.current(s.config.PublicOrigin)
	if err != nil || s.state.account(s.config, current != nil, current != nil, true) != nil {
		return result, ErrState
	}
	environment, err := s.config.providerEnvironment()
	if err != nil {
		return result, err
	}
	_, timeout, _ := s.config.durations()
	request, cancel := context.WithTimeout(ctx, timeout)
	result.Phase = "issuance"
	err = s.runner(request, s.binary, filepath.Join(s.config.StateDirectory, "lego"), s.arguments(), environment)
	requestError := request.Err()
	cancel()
	if err == nil && requestError != nil {
		err = requestError
	}
	if s.state.account(s.config, current != nil, err == nil, true) != nil {
		return result, ErrState
	}
	if err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if s.state.unchanged() != nil || s.publication.unchanged() != nil {
		return result, ErrState
	}
	result.Phase = "publication"
	result.Generation, result.Published, err = s.publication.publish(s.config)
	if err != nil {
		return result, err
	}
	result.Phase = "retention"
	if err := s.publication.prune(s.config.PublicOrigin, result.Generation.Name); err != nil {
		return result, err
	}
	result.Phase = "ready"
	return result, nil
}

// Run checks immediately, then periodically with jitter. Short-lived certificates
// shorten that interval; errors back off while preserving an already loaded pair.
// Lego retains its ACME account, ARI state and ordinary renewal decision.
func (s *Service) Run(ctx context.Context, report func(Result, error)) error {
	interval, _, _ := s.config.durations()
	failures := 0
	for ctx.Err() == nil {
		result, err := s.Once(ctx)
		if report != nil {
			report(result, err)
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrState) || errors.Is(err, ErrLocked) || errors.Is(err, ErrConfiguration) {
			return err
		}
		delay := interval
		if err != nil {
			if failures < 6 {
				failures++
			}
			delay = time.Minute * time.Duration(1<<(failures-1))
		} else {
			failures = 0
		}
		generation, readErr := s.publication.current(s.config.PublicOrigin)
		if readErr != nil {
			return readErr
		}
		if generation != nil {
			remaining := time.Until(generation.NotAfter)
			if remaining > 0 && remaining/10 < delay {
				delay = remaining / 10
			}
		}
		if delay < time.Second {
			delay = time.Second
		}
		delay += time.Duration(rand.Int64N(int64(delay/5) + 1))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

// LogLine intentionally contains only fixed states and an optional expiry time.
func LogLine(result Result, err error) string {
	if err != nil {
		phase := result.Phase
		switch phase {
		case "configuration", "issuance", "publication", "retention", "ready":
		default:
			phase = "state"
		}
		return "ACME issuer " + phase + " failed; published material was retained"
	}
	if result.Generation == nil {
		return "ACME issuer has no published certificate"
	}
	return "ACME issuer ready; published=" + strconv.FormatBool(result.Published) + "; expires=" + result.Generation.NotAfter.UTC().Format(time.RFC3339)
}
