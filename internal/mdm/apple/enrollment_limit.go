package apple

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"golang.org/x/time/rate"
)

type enrollmentBucket struct {
	limiter *rate.Limiter
	last    time.Time
}

type enrollmentLimiter struct {
	mu      sync.Mutex
	clients map[netip.Addr]enrollmentBucket
	global  *rate.Limiter
	claims  chan struct{}
}

func newEnrollmentLimiter() *enrollmentLimiter {
	return &enrollmentLimiter{clients: make(map[netip.Addr]enrollmentBucket), global: rate.NewLimiter(100, 200), claims: make(chan struct{}, 4)}
}

func (l *enrollmentLimiter) allow(r *http.Request, identity clientidentity.Policy) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if identity.IsGateway(r) {
		// The pinned gateway replaces this header with one source address. Never
		// trust a forwarded chain or an unverified direct client's header.
		host = r.Header.Get("X-Forwarded-For")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	if !l.global.Allow() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	bucket, exists := l.clients[ip]
	if !exists {
		if len(l.clients) >= 4096 {
			for key, entry := range l.clients {
				if now.Sub(entry.last) > 5*time.Minute {
					delete(l.clients, key)
				}
			}
			if len(l.clients) >= 4096 {
				return false
			}
		}
		bucket.limiter = rate.NewLimiter(2, 30)
	}
	bucket.last = now
	l.clients[ip] = bucket
	return bucket.limiter.Allow()
}
