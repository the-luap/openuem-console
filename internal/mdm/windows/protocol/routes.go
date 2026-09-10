// Package protocol defines the exact public native Windows device routes.
package protocol

import "net/http"

const (
	DiscoveryPath  = "/EnrollmentServer/Discovery.svc"
	PolicyPath     = "/EnrollmentServer/Policy.svc"
	EnrollmentPath = "/EnrollmentServer/Enrollment.svc"
	ManagementPath = "/mdm/windows/syncml"
)

// Path accepts only canonical request targets, without query parameters or
// aliases. Host trust and TLS authentication belong to the receiving server.
func Path(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	u := r.URL
	if u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.User != nil || u.Opaque != "" || (u.Scheme != "" && u.Scheme != "https") || (u.Host != "" && u.Host != r.Host) {
		return ""
	}
	switch u.Path {
	case DiscoveryPath, PolicyPath, EnrollmentPath, ManagementPath:
		return u.Path
	default:
		return ""
	}
}

// Public permits discovery probes and POST protocol messages only. It never
// makes administrator pages or alternative methods publicly reachable.
func Public(r *http.Request) bool {
	path := Path(r)
	return path != "" && (r.Method == http.MethodPost || path == DiscoveryPath && (r.Method == http.MethodGet || r.Method == http.MethodHead))
}
