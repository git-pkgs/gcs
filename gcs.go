// Package gcs provides a small Google Cloud Storage client built on the JSON API.
package gcs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	gcsScope             = "https://www.googleapis.com/auth/cloud-platform"
	gcsDefaultHost       = "https://storage.googleapis.com"
	maxErrorResponseSize = 4096
)

var (
	// ErrNotFound indicates that an object does not exist.
	ErrNotFound = errors.New("gcs object not found")

	// ErrSignedURLUnsupported indicates that the current credentials cannot sign URLs.
	ErrSignedURLUnsupported = errors.New("signed gcs URLs not supported by current credentials")
)

// ObjectInfo contains metadata for an object.
type ObjectInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
}

// Bucket provides access to a Google Cloud Storage bucket through the JSON API.
type Bucket struct {
	bucket     string
	client     *http.Client
	apiBase    string
	uploadBase string

	accessID   string
	privateKey []byte
	signBytes  func(context.Context, []byte) ([]byte, error)
}

// OpenBucket opens a Google Cloud Storage bucket from a gs:// URL.
func OpenBucket(ctx context.Context, urlStr string) (*Bucket, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parsing GCS URL: %w", err)
	}
	if u.Scheme != "gs" || u.Host == "" {
		return nil, fmt.Errorf("invalid GCS URL %q", urlStr)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("GCS URL must name a bucket, got path %q", u.Path)
	}

	host := gcsDefaultHost
	client := http.DefaultClient
	var accessID string
	var privateKey []byte

	if emulator := os.Getenv("STORAGE_EMULATOR_HOST"); emulator != "" {
		host = strings.TrimRight(emulator, "/")
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "http://" + host
		}
	} else {
		var credsJSON []byte
		var err error
		client, credsJSON, err = gcsHTTPClient(ctx)
		if err != nil {
			return nil, err
		}
		accessID, privateKey = readGCSCredentials(credsJSON)
		if accessID == "" && len(credsJSON) == 0 && metadata.OnGCE() {
			accessID, _ = metadata.EmailWithContext(ctx, "")
		}
	}

	g := &Bucket{
		bucket:     u.Host,
		client:     client,
		apiBase:    host + "/storage/v1",
		uploadBase: host + "/upload/storage/v1",
		accessID:   accessID,
		privateKey: privateKey,
	}
	if len(privateKey) == 0 && accessID != "" {
		g.signBytes = g.signBlob
	}
	return g, nil
}

func gcsHTTPClient(ctx context.Context) (*http.Client, []byte, error) {
	authCtx := context.WithoutCancel(ctx)
	creds, err := google.FindDefaultCredentials(authCtx, gcsScope)
	if err != nil {
		return nil, nil, fmt.Errorf("loading GCS default credentials: %w", err)
	}
	return oauth2.NewClient(authCtx, creds.TokenSource), creds.JSON, nil
}

func readGCSCredentials(credFileAsJSON []byte) (string, []byte) {
	var serviceAccount struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(credFileAsJSON, &serviceAccount); err == nil && serviceAccount.ClientEmail != "" {
		return serviceAccount.ClientEmail, []byte(serviceAccount.PrivateKey)
	}

	var impersonated struct {
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	}
	if err := json.Unmarshal(credFileAsJSON, &impersonated); err == nil {
		if email := serviceAccountFromImpersonationURL(impersonated.ServiceAccountImpersonationURL); email != "" {
			return email, nil
		}
	}

	return "", nil
}

func serviceAccountFromImpersonationURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	const marker = "/serviceAccounts/"
	idx := strings.Index(u.Path, marker)
	if idx == -1 {
		return ""
	}
	email := strings.TrimSuffix(u.Path[idx+len(marker):], ":generateAccessToken")
	email, _ = url.PathUnescape(email)
	return email
}

// Write stores an object and returns the number of bytes read from r.
func (g *Bucket) Write(ctx context.Context, path string, r io.Reader) (int64, error) {
	body := &countingReader{r: r}

	endpoint := g.uploadBase + "/b/" + url.PathEscape(g.bucket) + "/o"
	reqURL, _ := url.Parse(endpoint)
	q := reqURL.Query()
	q.Set("uploadType", "media")
	q.Set("name", path)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := g.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("uploading GCS object: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := g.checkResponse(resp, http.StatusOK); err != nil {
		return 0, fmt.Errorf("uploading GCS object: %w", err)
	}

	return body.n, nil
}

// Open reads an object. The caller must close the returned reader.
func (g *Bucket) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.objectURL(path)+"?alt=media", nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opening GCS object: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, ErrNotFound
	}
	if err := g.checkResponse(resp, http.StatusOK); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("opening GCS object: %w", err)
	}
	return resp.Body, nil
}

// Exists reports whether an object exists.
func (g *Bucket) Exists(ctx context.Context, path string) (bool, error) {
	_, err := g.attrs(ctx, path)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Delete removes an object. A missing object is not an error.
func (g *Bucket) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, g.objectURL(path), nil)
	if err != nil {
		return err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("deleting GCS object: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if err := g.checkResponse(resp, http.StatusNoContent); err != nil {
		return fmt.Errorf("deleting GCS object: %w", err)
	}
	return nil
}

// Size returns an object's size in bytes.
func (g *Bucket) Size(ctx context.Context, path string) (int64, error) {
	obj, err := g.attrs(ctx, path)
	if err != nil {
		return 0, err
	}
	return obj.size(), nil
}

// SignedURL returns a time-limited URL for reading an object.
func (g *Bucket) SignedURL(ctx context.Context, path string, expiry time.Duration) (string, error) {
	if g.accessID == "" {
		return "", ErrSignedURLUnsupported
	}

	expires := time.Now().Add(expiry)
	u := &url.URL{Path: fmt.Sprintf("/%s/%s", g.bucket, path)}
	stringToSign := fmt.Sprintf("GET\n\n\n%d\n%s", expires.Unix(), u.String())

	signed, err := g.sign(ctx, []byte(stringToSign))
	if err != nil {
		return "", fmt.Errorf("signing GCS URL: %w", err)
	}

	u.Scheme = "https"
	u.Host = "storage.googleapis.com"
	q := u.Query()
	q.Set("GoogleAccessId", g.accessID)
	q.Set("Expires", strconv.FormatInt(expires.Unix(), 10))
	q.Set("Signature", base64.StdEncoding.EncodeToString(signed))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// UsedSpace returns the total size of every object in the bucket.
func (g *Bucket) UsedSpace(ctx context.Context) (int64, error) {
	var total int64
	err := g.listPrefix(ctx, "", "nextPageToken,items(size)", func(item gcsObject) {
		total += item.size()
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

// ListPrefix returns metadata for objects whose names start with prefix.
func (g *Bucket) ListPrefix(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var objects []ObjectInfo
	err := g.listPrefix(ctx, prefix, "nextPageToken,items(name,size,updated)", func(item gcsObject) {
		objects = append(objects, ObjectInfo{
			Name:    item.Name,
			Size:    item.size(),
			ModTime: item.updated(),
		})
	})
	return objects, err
}

func (g *Bucket) listPrefix(ctx context.Context, prefix, fields string, visit func(gcsObject)) error {
	pageToken := ""

	for {
		reqURL, _ := url.Parse(g.apiBase + "/b/" + url.PathEscape(g.bucket) + "/o")
		q := reqURL.Query()
		q.Set("prefix", prefix)
		q.Set("fields", fields)
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		reqURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
		if err != nil {
			return err
		}
		resp, err := g.client.Do(req)
		if err != nil {
			return fmt.Errorf("listing GCS objects: %w", err)
		}
		if err := g.checkResponse(resp, http.StatusOK); err != nil {
			_ = resp.Body.Close()
			return fmt.Errorf("listing GCS objects: %w", err)
		}

		var page gcsListResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			_ = resp.Body.Close()
			return fmt.Errorf("decoding GCS list response: %w", err)
		}
		_ = resp.Body.Close()

		for _, item := range page.Items {
			visit(item)
		}
		if page.NextPageToken == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

func (g *Bucket) attrs(ctx context.Context, path string) (*gcsObject, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.objectURL(path), nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting GCS object attributes: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if err := g.checkResponse(resp, http.StatusOK); err != nil {
		return nil, fmt.Errorf("getting GCS object attributes: %w", err)
	}

	var obj gcsObject
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, fmt.Errorf("decoding GCS attributes: %w", err)
	}
	return &obj, nil
}

func (g *Bucket) objectURL(path string) string {
	return g.apiBase + "/b/" + url.PathEscape(g.bucket) + "/o/" + url.PathEscape(path)
}

func (g *Bucket) checkResponse(resp *http.Response, want int) error {
	if resp.StatusCode == want {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseSize))
	return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func (g *Bucket) sign(ctx context.Context, b []byte) ([]byte, error) {
	if len(g.privateKey) > 0 {
		key, err := parseGCSPrivateKey(g.privateKey)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	}
	if g.signBytes != nil {
		return g.signBytes(ctx, b)
	}
	return nil, ErrSignedURLUnsupported
}

func (g *Bucket) signBlob(ctx context.Context, payload []byte) ([]byte, error) {
	reqBody, err := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return nil, err
	}

	endpoint := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
		url.PathEscape(g.accessID) + ":signBlob"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling IAM signBlob: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := g.checkResponse(resp, http.StatusOK); err != nil {
		return nil, fmt.Errorf("calling IAM signBlob: %w", err)
	}

	var out struct {
		SignedBlob string `json:"signedBlob"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding IAM signBlob response: %w", err)
	}
	return base64.StdEncoding.DecodeString(out.SignedBlob)
}

func parseGCSPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	if block, _ := pem.Decode(key); block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return parsed, nil
}

type gcsObject struct {
	Name    string `json:"name"`
	Size    string `json:"size"`
	Updated string `json:"updated"`
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func (o gcsObject) size() int64 {
	n, _ := strconv.ParseInt(o.Size, 10, 64)
	return n
}

func (o gcsObject) updated() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, o.Updated)
	return t
}

type gcsListResponse struct {
	NextPageToken string      `json:"nextPageToken"`
	Items         []gcsObject `json:"items"`
}
