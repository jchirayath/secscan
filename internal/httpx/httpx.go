// Package httpx is the ONLY outbound HTTP client in the binary.
//
// Codebases that let every caller construct its own client end up with dozens
// of ad-hoc http.Client{} literals, no uniform timeout, no TLS floor, and a
// handful of places silently accepting any certificate. Here there is one
// client with a mandatory
// timeout and a TLS 1.2 floor, and ci/guards.sh fails the build on an
// http.Client literal or an InsecureSkipVerify anywhere else
// (ARCHITECTURE.md — Outbound HTTP).
package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a timeout-bounded, TLS-floored HTTP client.
type Client struct{ c *http.Client }

// New builds the client. A zero timeout is corrected rather than honoured: an
// unbounded outbound call is how a scanner hangs forever on a dead endpoint.
func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{c: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		// Credentials must not follow a redirect to another host: that is how
		// a token ends up at an attacker-controlled endpoint.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing cross-host redirect %s → %s", via[0].URL.Host, req.URL.Host)
			}
			return nil
		},
	}}
}

// PostForm posts application/x-www-form-urlencoded and returns the body.
func (c *Client) PostForm(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

// Get fetches a URL and returns the body.
func (c *Client) Get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Bounded read: a hostile or broken endpoint must not exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		// The body of a failed auth exchange can contain a code or token, so
		// it is summarised, never echoed wholesale.
		return nil, fmt.Errorf("%s %s: HTTP %d", req.Method, redactURL(req.URL), resp.StatusCode)
	}
	return body, nil
}

// redactURL strips query parameters, which routinely carry codes and tokens.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.RawQuery = ""
	return c.String()
}
