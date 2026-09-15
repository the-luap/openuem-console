package audit

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"strconv"
	"time"

	"github.com/open-uem/openuem-console/internal/security/exporttext"
)

func encodeCSV(events []Event) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"Time (UTC)", "Source", "Event ID", "Organization ID", "Site ID", "Actor", "Action", "Target", "Result"}); err != nil {
		return nil, err
	}
	for _, e := range events {
		row := []string{e.CreatedAt.UTC().Format(time.RFC3339Nano), e.Source, strconv.FormatInt(e.ID, 10), strconv.Itoa(e.TenantID), strconv.Itoa(e.SiteID), e.Actor, e.Action, e.Resource, e.Result}
		for i := range row {
			row[i] = exporttext.SpreadsheetCell(row[i])
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return nil, err
		}
		if b.Len() > 16<<20 {
			return nil, ErrTooLarge
		}
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func (s *Store) ExportCSV(ctx context.Context, actor string, f Filter) ([]byte, error) {
	return s.export(ctx, actor, f, encodeCSV)
}

func (s *Store) ExportJSON(ctx context.Context, actor string, f Filter) ([]byte, error) {
	return s.export(ctx, actor, f, func(events []Event) ([]byte, error) {
		data, err := json.Marshal(events)
		if len(data) > 16<<20 {
			return nil, ErrTooLarge
		}
		return data, err
	})
}

func (s *Store) export(ctx context.Context, actor string, f Filter, encode func([]Event) ([]byte, error)) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	select {
	case s.exports <- struct{}{}:
		defer func() { <-s.exports }()
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorize(ctx, tx, actor, f.Scope); err != nil {
		return nil, err
	}
	c, _ := decodeCursor(f, "")
	events, _, err := selectEvents(ctx, tx, f, c, 10001)
	if err != nil {
		return nil, err
	}
	var data []byte
	if len(events) > 10000 {
		err = ErrTooLarge
	} else {
		data, err = encode(events)
	}
	if err != nil {
		if err != ErrTooLarge {
			return nil, err
		}
		if auditErr := recordActivity(ctx, tx, actor, "audit.export", "failure", f, 0); auditErr != nil {
			return nil, auditErr
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return nil, commitErr
		}
		return nil, err
	}
	if err = recordActivity(ctx, tx, actor, "audit.export", "success", f, len(events)); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return data, nil
}
