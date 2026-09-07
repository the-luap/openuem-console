package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type OSRelease struct {
	Version          string   `json:"ProductVersion"`
	Build            string   `json:"Build"`
	PostingDate      string   `json:"PostingDate"`
	ExpirationDate   string   `json:"ExpirationDate"`
	SupportedDevices []string `json:"SupportedDevices"`
}
type SoftwareCatalog struct {
	PublicAssetSets map[string][]OSRelease `json:"PublicAssetSets"`
	AssetSets       map[string][]OSRelease `json:"AssetSets"`
}

func (c SoftwareCatalog) Releases(model string, now time.Time) []OSRelease {
	result := []OSRelease{}
	seen := map[string]bool{}
	for _, group := range []map[string][]OSRelease{c.PublicAssetSets, c.AssetSets} {
		for _, r := range group["iOS"] {
			if !versionPattern.MatchString(r.Version) {
				continue
			}
			posted, err := time.Parse("2006-01-02", r.PostingDate)
			if err != nil || now.Before(posted) {
				continue
			}
			expires, err := time.Parse("2006-01-02", r.ExpirationDate)
			if err != nil || !now.Before(expires.Add(24*time.Hour)) {
				continue
			}
			for _, supported := range r.SupportedDevices {
				if supported == model && !seen[r.Version+"/"+r.Build] {
					result = append(result, r)
					seen[r.Version+"/"+r.Build] = true
					break
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return CompareVersions(result[i].Version, result[j].Version) > 0 })
	return result
}

func (c SoftwareCatalog) Supports(d Device, p UpdatePolicy, now time.Time) bool {
	for _, r := range c.Releases(d.Model, now) {
		versionMatches := r.Version == p.TargetVersion || (strings.Count(p.TargetVersion, ".") == 1 && strings.HasPrefix(r.Version, p.TargetVersion+"."))
		if versionMatches && (p.TargetBuild == "" || p.TargetBuild == r.Build) {
			return true
		}
	}
	return false
}

func (s *Store) Catalog(ctx context.Context) (*SoftwareCatalog, *time.Time, error) {
	var data []byte
	var fetched *time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT document,fetched_at FROM mdm_apple_software_catalog WHERE singleton=true`).Scan(&data, &fetched); err != nil {
		return nil, nil, err
	}
	var c SoftwareCatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, nil, err
	}
	return &c, fetched, nil
}

// RefreshCatalog coordinates all replicas and follows Apple's request to query
// GDMF no more than once daily. Failed refreshes preserve the last good document.
func (s *Store) RefreshCatalog(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var attempted *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT attempted_at FROM mdm_apple_software_catalog WHERE singleton=true FOR UPDATE`).Scan(&attempted); err != nil {
		return err
	}
	if attempted != nil && time.Since(*attempted) < 24*time.Hour {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_software_catalog SET attempted_at=now() WHERE singleton=true`); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gdmf.apple.com/v2/pmv", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("unexpected Apple catalog redirect") }}
	res, fetchErr := client.Do(req)
	var data []byte
	if fetchErr == nil {
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			fetchErr = fmt.Errorf("Apple software catalog returned HTTP %d", res.StatusCode)
		} else {
			data, fetchErr = io.ReadAll(io.LimitReader(res.Body, 8<<20))
		}
	}
	if fetchErr == nil {
		var catalog SoftwareCatalog
		fetchErr = json.Unmarshal(data, &catalog)
		if fetchErr == nil && len(catalog.PublicAssetSets["iOS"])+len(catalog.AssetSets["iOS"]) == 0 {
			fetchErr = errors.New("Apple software catalog contains no iOS releases")
		}
	}
	if fetchErr != nil {
		_, err = s.db.ExecContext(ctx, `UPDATE mdm_apple_software_catalog SET last_error=$1 WHERE singleton=true`, fetchErr.Error())
		if err != nil {
			return err
		}
		return fetchErr
	}
	_, err = s.db.ExecContext(ctx, `UPDATE mdm_apple_software_catalog SET document=$1,fetched_at=now(),last_error='' WHERE singleton=true`, data)
	return err
}

func (s *Store) validateCatalogPolicy(ctx context.Context, tx *sql.Tx, d *Device, p *UpdatePolicy) error {
	var data []byte
	var fetched *time.Time
	if err := tx.QueryRowContext(ctx, `SELECT document,fetched_at FROM mdm_apple_software_catalog WHERE singleton=true`).Scan(&data, &fetched); err != nil {
		return err
	}
	if fetched == nil || time.Since(*fetched) > 48*time.Hour {
		return errors.New("a recent Apple software catalog is required; check the public MDM service and its network access")
	}
	var catalog SoftwareCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return err
	}
	if !catalog.Supports(*d, *p, time.Now()) {
		return errors.New("this OS version/build is not currently available from Apple for the selected device model")
	}
	return nil
}
