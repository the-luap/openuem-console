package gateway

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Gateway tracks upgraded connections because http.Server.Shutdown does not
// close hijacked WebSockets. Close ends those streams and prevents new upgrades.
type Gateway struct {
	handler     http.Handler
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]struct{}
	slots       chan struct{}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.handler.ServeHTTP(w, r) }

func (g *Gateway) Close() error {
	g.mu.Lock()
	g.closed = true
	connections := make([]net.Conn, 0, len(g.connections))
	for conn := range g.connections {
		connections = append(connections, conn)
	}
	g.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return nil
}

func (g *Gateway) serveAgent(proxy http.Handler, w http.ResponseWriter, r *http.Request) {
	if !nativeWebSocket(r) {
		http.Error(w, "native agent WebSocket upgrade required", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		http.Error(w, "agent channel temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		w.Header().Set("Retry-After", "5")
		http.Error(w, "agent channel temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	proxy.ServeHTTP(&agentWriter{ResponseWriter: w, gateway: g}, r)
}

func nativeWebSocket(r *http.Request) bool {
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	// Native NATS clients send neither browser Origin nor cookies. This route
	// deliberately provides no browser or HTTP credential authentication flow.
	for _, name := range []string{"Origin", "Cookie", "Authorization", "Proxy-Authorization", "Sec-WebSocket-Protocol"} {
		if len(r.Header.Values(name)) != 0 {
			return false
		}
	}
	if len(r.Header.Values("Upgrade")) != 1 || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || len(r.Header.Values("Sec-WebSocket-Version")) != 1 || r.Header.Get("Sec-WebSocket-Version") != "13" || len(r.Header.Values("Sec-WebSocket-Key")) != 1 {
		return false
	}
	key, err := base64.StdEncoding.Strict().DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

type agentWriter struct {
	http.ResponseWriter
	gateway *Gateway
}

func (w *agentWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *agentWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, buffer, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// The HTTP request deadlines must not terminate a healthy long-lived
	// agent stream. NATS enforces authentication timeout, pings and user expiry.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	tracked := &agentConn{Conn: conn, gateway: w.gateway}
	w.gateway.mu.Lock()
	if w.gateway.closed {
		w.gateway.mu.Unlock()
		_ = conn.Close()
		return nil, nil, errors.New("gateway is closing")
	}
	w.gateway.connections[tracked] = struct{}{}
	w.gateway.mu.Unlock()
	return tracked, buffer, nil
}

type agentConn struct {
	net.Conn
	gateway *Gateway
}

func (c *agentConn) Close() error {
	c.gateway.mu.Lock()
	delete(c.gateway.connections, c)
	c.gateway.mu.Unlock()
	return c.Conn.Close()
}
