// Package auth gates the dashboard. Three modes (ARCHITECTURE.md — Authentication):
//
//	entra — this binary performs the OIDC authorization-code flow with PKCE
//	        against a single tenant and issues an HMAC-signed session cookie.
//	proxy — already behind App Service Easy Auth / Entra App Proxy; trust the
//	        injected identity headers, but ONLY from a declared trusted peer.
//	local — no authentication, permitted only on a loopback bind.
//
// No external OIDC library: Go's crypto, net/http and encoding/json cover the
// whole requirement.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/clock"
	"github.com/jchirayath/secscan/internal/config"
	"github.com/jchirayath/secscan/internal/httpx"
	"github.com/jchirayath/secscan/internal/rbac"
)

// Principal is an authenticated caller. Email and Role are carried separately
// everywhere downstream — the caller-AND-role rule.
type Principal struct {
	Email string    `json:"email"`
	Name  string    `json:"name"`
	Role  rbac.Role `json:"role"`
	Exp   time.Time `json:"exp"`
}

const cookieName = "secscan_session"

// Authenticator resolves a request to a Principal.
type Authenticator interface {
	// Authenticate returns the caller, or an error if the request is not
	// authenticated. It never returns a partially-trusted principal.
	Authenticate(r *http.Request) (Principal, error)
	// Mode names the mode, for the UI banner and audit records.
	Mode() string
	// Routes lets a mode register its own endpoints (the OIDC dance).
	Routes(mux *http.ServeMux)
}

// New builds the Authenticator for the configured mode.
func New(cfg *config.Config) (Authenticator, error) {
	switch cfg.AuthMode {
	case "local":
		// Refusing rather than warning: a warning on a public bind is how
		// unauthenticated dashboards end up on the internet.
		if !cfg.LoopbackOnly() {
			return nil, fmt.Errorf(
				"auth mode 'local' requires a loopback bind, but SECSCAN_BIND=%q is externally reachable.\n"+
					"Use --auth entra (or proxy) for a non-loopback listener", cfg.Bind)
		}
		slog.Warn("AUTHENTICATION DISABLED — 'local' mode, loopback only",
			slog.String("bind", cfg.Bind))
		return &localAuth{}, nil

	case "proxy":
		nets, err := parseCIDRs(cfg.TrustedProxies)
		if err != nil {
			return nil, err
		}
		return &proxyAuth{trusted: nets}, nil

	case "entra":
		return newEntraAuth(cfg)
	}
	return nil, fmt.Errorf("unknown auth mode %q", cfg.AuthMode)
}

// ------------------------------------------------------------------ local

type localAuth struct{}

func (localAuth) Mode() string            { return "local" }
func (localAuth) Routes(_ *http.ServeMux) {}
func (localAuth) Authenticate(_ *http.Request) (Principal, error) {
	return Principal{Email: "local@localhost", Name: "Local user", Role: rbac.RoleAdmin}, nil
}

// ------------------------------------------------------------------ proxy

type proxyAuth struct{ trusted []*net.IPNet }

func (proxyAuth) Mode() string            { return "proxy" }
func (proxyAuth) Routes(_ *http.ServeMux) {}

// Authenticate trusts App Service Easy Auth headers — but only from a peer in
// the trusted list. Header trust without a peer check is a complete
// authentication bypass: anyone who can reach the port sets their own identity.
func (p *proxyAuth) Authenticate(r *http.Request) (Principal, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !p.trustedPeer(ip) {
		// Someone presenting identity headers from an untrusted peer is
		// attempting a spoof, and that is worth its own log line.
		if r.Header.Get("X-MS-CLIENT-PRINCIPAL-NAME") != "" {
			slog.Warn("identity headers from untrusted peer — rejected as spoofing attempt",
				slog.String("peer", host),
				slog.String("claimed", r.Header.Get("X-MS-CLIENT-PRINCIPAL-NAME")))
		}
		return Principal{}, fmt.Errorf("peer %s is not a trusted proxy", host)
	}

	email := r.Header.Get("X-MS-CLIENT-PRINCIPAL-NAME")
	if email == "" {
		return Principal{}, fmt.Errorf("no identity header from proxy")
	}
	role := rbac.FromClaims(splitList(r.Header.Get("X-MS-CLIENT-PRINCIPAL-ROLES")))
	return Principal{Email: email, Name: email, Role: role}, nil
}

func (p *proxyAuth) trustedPeer(ip net.IP) bool {
	for _, n := range p.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDRs(in []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range in {
		if !strings.Contains(s, "/") {
			// Accept a bare IP as a /32 or /128 — a common operator shorthand.
			if ip := net.ParseIP(s); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				_, n, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", s, bits))
				out = append(out, n)
				continue
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("SECSCAN_TRUSTED_PROXIES: %q is not a CIDR: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// ------------------------------------------------------------------ entra

type entraAuth struct {
	cfg    *config.Config
	client *httpx.Client
	// pending holds in-flight OIDC states → PKCE verifier. Bounded and
	// short-lived; a restart simply invalidates in-flight logins.
	pending map[string]pendingLogin
}

type pendingLogin struct {
	verifier string
	nonce    string
	redirect string
	at       time.Time
}

func newEntraAuth(cfg *config.Config) (*entraAuth, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("SECSCAN_BASE_URL is required in entra mode (the redirect URI is derived from it)")
	}
	return &entraAuth{
		cfg:     cfg,
		client:  httpx.New(cfg.HTTPTimeout),
		pending: map[string]pendingLogin{},
	}, nil
}

func (e *entraAuth) Mode() string { return "entra" }

func (e *entraAuth) redirectURI() string { return e.cfg.BaseURL + "/auth/callback" }

func (e *entraAuth) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", e.handleLogin)
	mux.HandleFunc("GET /auth/callback", e.handleCallback)
	mux.HandleFunc("GET /auth/logout", e.handleLogout)
}

func (e *entraAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier := randB64(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randB64(16)
	nonce := randB64(16)

	e.sweepPending()
	e.pending[state] = pendingLogin{
		verifier: verifier, nonce: nonce, at: clock.Now(),
		redirect: safeRedirect(r.URL.Query().Get("next")),
	}

	q := url.Values{
		"client_id":             {e.cfg.EntraClientID},
		"response_type":         {"code"},
		"redirect_uri":          {e.redirectURI()},
		"response_mode":         {"query"},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, e.authority()+"/oauth2/v2.0/authorize?"+q.Encode(), http.StatusFound)
}

func (e *entraAuth) authority() string {
	return "https://login.microsoftonline.com/" + e.cfg.EntraTenantID
}

func (e *entraAuth) handleCallback(w http.ResponseWriter, r *http.Request) {
	if msg := r.URL.Query().Get("error_description"); msg != "" {
		http.Error(w, "sign-in failed: "+msg, http.StatusUnauthorized)
		return
	}
	state := r.URL.Query().Get("state")
	pend, ok := e.pending[state]
	if !ok {
		// No matching state means CSRF, a replayed callback, or a restart.
		http.Error(w, "sign-in state not recognised — start again at /auth/login", http.StatusBadRequest)
		return
	}
	delete(e.pending, state)

	form := url.Values{
		"client_id":     {e.cfg.EntraClientID},
		"client_secret": {e.cfg.EntraClientSecret},
		"code":          {r.URL.Query().Get("code")},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {e.redirectURI()},
		"code_verifier": {pend.verifier},
		"scope":         {"openid profile email"},
	}
	body, err := e.client.PostForm(r.Context(), e.authority()+"/oauth2/v2.0/token", form)
	if err != nil {
		slog.Error("token exchange failed", slog.String("err", err.Error()))
		http.Error(w, "sign-in failed at token exchange", http.StatusBadGateway)
		return
	}

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		http.Error(w, "sign-in failed: no id_token", http.StatusBadGateway)
		return
	}

	claims, err := parseIDToken(tok.IDToken)
	if err != nil {
		http.Error(w, "sign-in failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	// The id_token arrived over a direct TLS connection to the tenant's token
	// endpoint, so its authenticity rests on that channel (OIDC Core §3.1.3.7
	// permits skipping signature validation for this exact case). We still
	// enforce the claims that bind it to *this* request.
	if claims.Nonce != pend.nonce {
		http.Error(w, "sign-in failed: nonce mismatch", http.StatusBadRequest)
		return
	}
	if claims.Aud != e.cfg.EntraClientID {
		http.Error(w, "sign-in failed: token audience mismatch", http.StatusBadRequest)
		return
	}
	if !strings.Contains(claims.Iss, e.cfg.EntraTenantID) {
		http.Error(w, "sign-in failed: token issuer is not this tenant", http.StatusBadRequest)
		return
	}
	if clock.Now().After(time.Unix(claims.Exp, 0)) {
		http.Error(w, "sign-in failed: token already expired", http.StatusBadRequest)
		return
	}

	email := firstNonEmpty(claims.Email, claims.PreferredUsername, claims.UPN)
	if email == "" {
		http.Error(w, "sign-in failed: no email claim", http.StatusBadRequest)
		return
	}
	if !e.domainAllowed(email) {
		slog.Warn("sign-in rejected by domain allow-list", slog.String("email", email))
		http.Error(w, "your account's domain is not permitted here", http.StatusForbidden)
		return
	}

	role := rbac.FromClaims(claims.Roles)
	for _, a := range e.cfg.AdminEmails {
		if strings.EqualFold(a, email) {
			role = rbac.RoleAdmin
		}
	}

	p := Principal{
		Email: email,
		Name:  firstNonEmpty(claims.Name, email),
		Role:  role,
		Exp:   clock.Now().Add(e.cfg.SessionTTL),
	}
	setSessionCookie(w, p, e.cfg)
	slog.Info("sign-in", slog.String("principal", p.Email), slog.String("role", string(p.Role)))
	http.Redirect(w, r, pend.redirect, http.StatusFound)
}

func (e *entraAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, e.authority()+"/oauth2/v2.0/logout?post_logout_redirect_uri="+
		url.QueryEscape(e.cfg.BaseURL), http.StatusFound)
}

func (e *entraAuth) domainAllowed(email string) bool {
	if len(e.cfg.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	dom := strings.ToLower(email[at+1:])
	for _, d := range e.cfg.AllowedDomains {
		if strings.EqualFold(d, dom) {
			return true
		}
	}
	return false
}

func (e *entraAuth) Authenticate(r *http.Request) (Principal, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return Principal{}, fmt.Errorf("no session")
	}
	return verifySession(c.Value, e.cfg)
}

func (e *entraAuth) sweepPending() {
	cutoff := clock.Now().Add(-10 * time.Minute)
	for k, v := range e.pending {
		if v.at.Before(cutoff) {
			delete(e.pending, k)
		}
	}
}

// ---------------------------------------------------------------- session

// setSessionCookie issues the signed cookie. Signed, not encrypted: assume the
// browser can read the contents; the signature is what stops forgery.
func setSessionCookie(w http.ResponseWriter, p Principal, cfg *config.Config) {
	payload, _ := json.Marshal(p)
	b := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(b, cfg.SessionSecret)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    b + "." + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  p.Exp,
	})
}

func verifySession(v string, cfg *config.Config) (Principal, error) {
	i := strings.LastIndex(v, ".")
	if i < 0 {
		return Principal{}, fmt.Errorf("malformed session")
	}
	body, sig := v[:i], v[i+1:]
	// Constant-time compare: a timing oracle on the signature is a forgery
	// oracle.
	if subtle.ConstantTimeCompare([]byte(sig), []byte(sign(body, cfg.SessionSecret))) != 1 {
		return Principal{}, fmt.Errorf("bad session signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Principal{}, fmt.Errorf("malformed session payload")
	}
	var p Principal
	if err := json.Unmarshal(raw, &p); err != nil {
		return Principal{}, fmt.Errorf("malformed session json")
	}
	if clock.Now().After(p.Exp) {
		return Principal{}, fmt.Errorf("session expired")
	}
	if !rbac.Valid(string(p.Role)) {
		return Principal{}, fmt.Errorf("session carries unknown role")
	}
	return p, nil
}

func sign(msg, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ---------------------------------------------------------------- claims

type idClaims struct {
	Aud               string   `json:"aud"`
	Iss               string   `json:"iss"`
	Exp               int64    `json:"exp"`
	Nonce             string   `json:"nonce"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	UPN               string   `json:"upn"`
	Roles             []string `json:"roles"`
	Groups            []string `json:"groups"`
}

func parseIDToken(tok string) (idClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return idClaims{}, fmt.Errorf("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idClaims{}, fmt.Errorf("id_token payload is not base64url")
	}
	var c idClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return idClaims{}, fmt.Errorf("id_token payload is not JSON")
	}
	c.Roles = append(c.Roles, c.Groups...)
	return c, nil
}

// ---------------------------------------------------------------- helpers

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// safeRedirect prevents an open redirect: only same-site paths are honoured.
func safeRedirect(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

var _ = context.Background
