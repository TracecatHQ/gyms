package tracecat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL *url.URL
	apiKey  string
	http    *http.Client
}

func NewClient(rawURL, apiKey string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(rawURL, "/") + "/")
	if err != nil {
		return nil, fmt.Errorf("parse api_url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("api_url must be an absolute URL")
	}
	return &Client{baseURL: u, apiKey: apiKey, http: &http.Client{Timeout: 120 * time.Second}}, nil
}

func (c *Client) request(ctx context.Context, method, path, workspaceID, contentType string, body io.Reader, out any) (int, error) {
	u, err := c.baseURL.Parse(strings.TrimPrefix(path, "/"))
	if err != nil {
		return 0, err
	}
	if workspaceID != "" {
		q := u.Query()
		q.Set("workspace_id", workspaceID)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if workspaceID != "" {
		req.Header.Set("x-tracecat-role-workspace-id", workspaceID)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("Tracecat %s %s returned %d: %s", method, u.Path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode Tracecat response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func (c *Client) JSON(ctx context.Context, method, path, workspaceID string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
	}
	return c.request(ctx, method, path, workspaceID, "application/json", reader, out)
}

func (c *Client) UploadWorkflow(ctx context.Context, workspaceID, filename string, yaml []byte, out any) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(yaml); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodPost, "/workflows", workspaceID, writer.FormDataContentType(), &body, out)
	return err
}

func responseID(value map[string]any) string {
	if id, ok := value["id"].(string); ok {
		return id
	}
	if nested, ok := value["mcp_integration"].(map[string]any); ok {
		if id, ok := nested["id"].(string); ok {
			return id
		}
	}
	return ""
}
