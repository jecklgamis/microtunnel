package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jecklgamis/microtunnel/internal/admin"
)

// Client talks to a relay's admin socket.
type Client struct {
	hc *http.Client
}

// NewClient returns a Client for the unix socket at path.
func NewClient(socketPath string) *Client {
	return &Client{hc: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}}
}

// APIError is an error response from the server.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	// The host part is ignored by the unix-socket dialer.
	req, err := http.NewRequestWithContext(ctx, method, "http://microtunnel"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var ae apiError
		if json.Unmarshal(data, &ae) != nil || ae.Error == "" {
			ae.Error = fmt.Sprintf("admin API returned HTTP %d", resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: ae.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Status returns the relay's status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// List returns every configured peer with live state.
func (c *Client) List(ctx context.Context) ([]PeerInfo, error) {
	var out []PeerInfo
	if err := c.do(ctx, http.MethodGet, "/v1/peers", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Add registers a peer.
func (c *Client) Add(ctx context.Context, req AddRequest) (*admin.Registration, error) {
	var reg admin.Registration
	if err := c.do(ctx, http.MethodPost, "/v1/peers", req, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

// Remove removes a peer by name.
func (c *Client) Remove(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/peers/"+url.PathEscape(name), nil, nil)
}
