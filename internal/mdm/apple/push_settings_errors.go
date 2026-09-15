package apple

import "errors"

// Push setting failures have stable identities so callers can present known
// validation guidance without displaying wrapped database or transport details.
var (
	ErrPushOrganization     = errors.New("organization is required")
	ErrPushPublicURL        = errors.New("public MDM URL must be an HTTPS origin without a path, query or credentials")
	ErrPushOrganizationName = errors.New("organization name is required")
	ErrPushKeyPair          = errors.New("invalid APNs certificate/key pair")
	ErrPushTopicMissing     = errors.New("certificate does not contain an Apple MDM push topic")
	ErrPushValidity         = errors.New("APNs certificate is not currently valid")
	ErrPushTopicChanged     = errors.New("APNs renewal must preserve the existing push topic")
	ErrPushURLInUse         = errors.New("the public MDM URL cannot change while enrollments or active ADE profiles use it")
)
