package apple

import (
	"context"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrUpdatePolicyReview = errors.New("the configured update policy changed; reload the device before retrying")

// SetReviewedDeviceUpdatePolicy compares the reviewed configured values while
// holding current authority and the native device's exclusive mutation lock.
// Device progress does not invalidate a review; a changed configuration does.
func (s *Store) SetReviewedDeviceUpdatePolicy(ctx context.Context, scope Scope, id, expected string, policy *UpdatePolicy, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	if !profileRevisionUUID(id) || !updateGroupPolicyToken.MatchString(expected) {
		return ErrUpdatePolicyReview
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.setUpdatePolicy(ctx, scope, []string{id}, policy, actor, permissions, map[string]string{id: expected})
}
