package windows

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrUpdateGroup         = errors.New("invalid native Windows update group selection")
	ErrUpdateGroupConflict = errors.New("native Windows update group changed")
	ErrUpdateGroupLarge    = errors.New("native Windows update group selection exceeds bounds")
)

// UpdateGroupSource is captured inside the rollout's authenticated encrypted
// target intent. Later group edits cannot rewrite the original source labels.
type UpdateGroupSource struct {
	ID       string                    `json:"-" xml:"-" yaml:"-"`
	Revision int                       `json:"-" xml:"-" yaml:"-"`
	Name     string                    `json:"-" xml:"-" yaml:"-"`
	Rule     inventory.DeviceGroupRule `json:"-" xml:"-" yaml:"-"`
}
type UpdateGroupPreview struct {
	Source   UpdateGroupSource       `json:"-" xml:"-" yaml:"-"`
	Targets  []string                `json:"-" xml:"-" yaml:"-"`
	Excluded []inventory.DeviceEntry `json:"-" xml:"-" yaml:"-"`
}
type updateGroupIntent struct {
	ID       string
	Revision int
	Name     string
	Rule     inventory.DeviceGroupRule
}

func sealUpdateGroupSource(g *UpdateGroupSource) *updateGroupIntent {
	if g == nil {
		return nil
	}
	return &updateGroupIntent{ID: g.ID, Revision: g.Revision, Name: g.Name, Rule: g.Rule}
}
func (g *updateGroupIntent) source() *UpdateGroupSource {
	if g == nil {
		return nil
	}
	return &UpdateGroupSource{ID: g.ID, Revision: g.Revision, Name: g.Name, Rule: g.Rule}
}
func (UpdateGroupSource) String() string      { return "[protected Windows group source]" }
func (s UpdateGroupSource) GoString() string  { return s.String() }
func (UpdateGroupPreview) String() string     { return "[protected Windows group preview]" }
func (p UpdateGroupPreview) GoString() string { return p.String() }

func validUpdateGroupSource(g *UpdateGroupSource) bool {
	return g != nil && canonicalInvitationID(g.ID) && g.Revision > 0 && g.Revision <= 2147483647 && (inventory.DeviceGroupDefinition{Name: g.Name, Rule: g.Rule}).Valid()
}
func updateGroupError(err error) error {
	switch {
	case errors.Is(err, inventory.ErrGroupConflict):
		return ErrUpdateGroupConflict
	case errors.Is(err, inventory.ErrGroupInvalid), errors.Is(err, inventory.ErrReportFilter):
		return ErrUpdateGroup
	case errors.Is(err, inventory.ErrGroupSnapshotLarge):
		return ErrUpdateGroupLarge
	case errors.Is(err, inventory.ErrNotFound):
		return ErrNotFound
	default:
		return err
	}
}
func (s *Store) updateGroupPreviewTx(ctx context.Context, tx *sql.Tx, actor string, scope access.Scope, sources inventory.DeviceSources, id string, revision int) (*UpdateGroupPreview, error) {
	if !sources.Windows {
		return nil, ErrUpdateGroup
	}
	snapshot, err := inventory.DeviceGroupSnapshotTransaction(ctx, tx, s.permissions, actor, scope, sources, id, revision)
	if err != nil {
		return nil, updateGroupError(err)
	}
	g := snapshot.Group
	preview := &UpdateGroupPreview{Source: UpdateGroupSource{ID: g.ID, Revision: g.Revision, Name: g.Name, Rule: g.Rule}, Targets: []string{}, Excluded: []inventory.DeviceEntry{}}
	for _, entry := range snapshot.Entries {
		if entry.Kind == "windows" {
			preview.Targets = append(preview.Targets, entry.ID)
		} else {
			preview.Excluded = append(preview.Excluded, entry)
		}
	}
	slices.Sort(preview.Targets)
	if len(preview.Targets) == 0 {
		return nil, ErrUpdateGroup
	}
	return preview, nil
}

// PreviewUpdateGroup selects native Windows members and explains all other
// management identities as exclusions. This read does not admit device work.
func (s *Store) PreviewUpdateGroup(ctx context.Context, actor string, scope access.Scope, sources inventory.DeviceSources, id string, revision int) (*UpdateGroupPreview, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorizeUpdateRing(ctx, tx, actor, scope); err != nil {
		return nil, err
	}
	preview, err := s.updateGroupPreviewTx(ctx, tx, actor, scope, sources, id, revision)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return preview, nil
}

// AssignUpdateRingFromGroup retains the exact reviewed target list. New work
// re-evaluates the current group under the admission transaction and rejects any
// different native Windows membership. An exact replay uses the original intent.
func (s *Store) AssignUpdateRingFromGroup(ctx context.Context, actor string, scope access.Scope, ringID string, ringRevision int64, requestKey string, devices []string, remove bool, validFor time.Duration, sources inventory.DeviceSources, groupID string, groupRevision int) (*UpdateRollout, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !sources.Windows || !canonicalInvitationID(groupID) || groupRevision < 1 || groupRevision > 2147483647 {
		return nil, ErrUpdateGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	selection := &updateGroupSelection{ID: groupID, Revision: groupRevision, Sources: sources}
	rollout, err := s.assignUpdateRingTx(ctx, tx, actor, scope, ringID, ringRevision, requestKey, devices, remove, validFor, nil, selection)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return rollout, nil
}

type updateGroupSelection struct {
	ID       string
	Revision int
	Sources  inventory.DeviceSources
}

func matchesUpdateGroupSelection(source *UpdateGroupSource, selection *updateGroupSelection) bool {
	if selection == nil {
		return source == nil
	}
	return source != nil && source.ID == selection.ID && source.Revision == selection.Revision
}
