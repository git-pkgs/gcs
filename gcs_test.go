package gcs

import (
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
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testAccessID   = "service@example.com"
	testRSAKeyBits = 2048
)

func TestBucketRoundTripWithEmulator(t *testing.T) {
	fake := &fakeGCS{t: t, objects: map[string]string{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	t.Setenv("STORAGE_EMULATOR_HOST", server.URL)

	ctx := context.Background()
	store, err := OpenBucket(ctx, "gs://test-bucket")
	if err != nil {
		t.Fatalf("OpenBucket failed: %v", err)
	}

	size, err := store.Write(ctx, "npm/pkg/file.tgz", strings.NewReader("content"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if size != int64(len("content")) {
		t.Fatalf("Write returned size=%d", size)
	}

	exists, err := store.Exists(ctx, "npm/pkg/file.tgz")
	if err != nil || !exists {
		t.Fatalf("Exists = %v, %v; want true, nil", exists, err)
	}

	r, err := store.Open(ctx, "npm/pkg/file.tgz")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	data, _ := io.ReadAll(r)
	_ = r.Close()
	if string(data) != "content" {
		t.Fatalf("Open content = %q, want content", data)
	}

	objectSize, err := store.Size(ctx, "npm/pkg/file.tgz")
	if err != nil || objectSize != int64(len("content")) {
		t.Fatalf("Size = %d, %v", objectSize, err)
	}

	usedSpace, err := store.UsedSpace(ctx)
	if err != nil || usedSpace != int64(len("content")) {
		t.Fatalf("UsedSpace = %d, %v", usedSpace, err)
	}

	list, err := store.ListPrefix(ctx, "npm/")
	if err != nil {
		t.Fatalf("ListPrefix failed: %v", err)
	}
	if len(list) != 1 || list[0].Name != "npm/pkg/file.tgz" {
		t.Fatalf("ListPrefix = %#v", list)
	}
	wantFields := strings.Join([]string{
		"nextPageToken,items(size)",
		"nextPageToken,items(size)",
		"nextPageToken,items(name,size,updated)",
		"nextPageToken,items(name,size,updated)",
	}, ";")
	if got := strings.Join(fake.listFields, ";"); got != wantFields {
		t.Fatalf("list fields = %q, want %q", got, wantFields)
	}

	if err := store.Delete(ctx, "npm/pkg/file.tgz"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	exists, err = store.Exists(ctx, "npm/pkg/file.tgz")
	if err != nil || exists {
		t.Fatalf("Exists after delete = %v, %v; want false, nil", exists, err)
	}

	reader, err := store.Open(ctx, "npm/pkg/file.tgz")
	if reader != nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open missing object = %v, %v; want nil, ErrNotFound", reader, err)
	}
	if err := store.Delete(ctx, "npm/pkg/file.tgz"); err != nil {
		t.Fatalf("Delete missing object failed: %v", err)
	}
	if _, err := store.SignedURL(ctx, "npm/pkg/file.tgz", time.Minute); !errors.Is(err, ErrSignedURLUnsupported) {
		t.Fatalf("SignedURL with emulator = %v, want ErrSignedURLUnsupported", err)
	}
}

type fakeGCS struct {
	t          *testing.T
	objects    map[string]string
	listFields []string
}

func (f *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/test-bucket/o":
		name := r.URL.Query().Get("name")
		data, _ := io.ReadAll(r.Body)
		f.objects[name] = string(data)
		writeJSON(w, gcsObject{Name: name, Size: strconv.Itoa(len(data)), Updated: time.Now().UTC().Format(time.RFC3339Nano)})
	case r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/test-bucket/o":
		f.listFields = append(f.listFields, r.URL.Query().Get("fields"))
		if r.URL.Query().Get("pageToken") == "" {
			writeJSON(w, gcsListResponse{NextPageToken: "next"})
			return
		}
		prefix := r.URL.Query().Get("prefix")
		page := gcsListResponse{}
		for name, data := range f.objects {
			if strings.HasPrefix(name, prefix) {
				page.Items = append(page.Items, gcsObject{Name: name, Size: strconv.Itoa(len(data)), Updated: time.Now().UTC().Format(time.RFC3339Nano)})
			}
		}
		sort.Slice(page.Items, func(i, j int) bool { return page.Items[i].Name < page.Items[j].Name })
		writeJSON(w, page)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/storage/v1/b/test-bucket/o/"):
		name := objectNameFromPath(r.URL.Path)
		data, ok := f.objects[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("alt") == "media" {
			_, _ = io.WriteString(w, data)
			return
		}
		writeJSON(w, gcsObject{Name: name, Size: strconv.Itoa(len(data)), Updated: time.Now().UTC().Format(time.RFC3339Nano)})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/storage/v1/b/test-bucket/o/"):
		name := objectNameFromPath(r.URL.Path)
		if _, ok := f.objects[name]; !ok {
			http.NotFound(w, r)
			return
		}
		delete(f.objects, name)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}
}

func TestOpenBucketRejectsInvalidURLs(t *testing.T) {
	t.Setenv("STORAGE_EMULATOR_HOST", "http://127.0.0.1")

	for _, rawURL := range []string{"", "s3://bucket", "gs://", "gs://bucket/prefix"} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := OpenBucket(context.Background(), rawURL); err == nil {
				t.Fatalf("OpenBucket(%q) returned nil error", rawURL)
			}
		})
	}
}

func TestOpenBucketCredentialsOutliveContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeJSON(w, map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/resource":
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("Authorization = %q, want Bearer test-token", got)
				http.Error(w, "invalid authorization", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	credentials := fmt.Sprintf(`{
		"type": "authorized_user",
		"client_id": "test-client",
		"client_secret": "test-secret",
		"refresh_token": "test-refresh-token",
		"token_uri": %q
	}`, server.URL+"/token")
	credentialsPath := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentialsPath, []byte(credentials), 0o600); err != nil {
		t.Fatalf("writing credentials: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentialsPath)
	t.Setenv("STORAGE_EMULATOR_HOST", "")

	ctx, cancel := context.WithCancel(context.Background())
	bucket, err := OpenBucket(ctx, "gs://test-bucket")
	if err != nil {
		t.Fatalf("OpenBucket failed: %v", err)
	}
	cancel()

	resp, err := bucket.client.Get(server.URL + "/resource")
	if err != nil {
		t.Fatalf("authenticated request after context cancellation failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("authenticated request status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestReadGCSCredentials(t *testing.T) {
	tests := []struct {
		name        string
		credentials string
		accessID    string
		privateKey  string
	}{
		{
			name:        "service account",
			credentials: `{"client_email":"` + testAccessID + `","private_key":"private-key"}`,
			accessID:    testAccessID,
			privateKey:  "private-key",
		},
		{
			name:        "impersonated service account",
			credentials: `{"service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service%40example.com:generateAccessToken"}`,
			accessID:    testAccessID,
		},
		{name: "invalid JSON", credentials: "{"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accessID, privateKey := readGCSCredentials([]byte(test.credentials))
			if accessID != test.accessID || string(privateKey) != test.privateKey {
				t.Fatalf("readGCSCredentials = %q, %q", accessID, privateKey)
			}
		})
	}
}

func TestGCSSignedURLWithPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, testRSAKeyBits)
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling PKCS8 private key: %v", err)
	}

	keys := map[string][]byte{
		"PKCS1": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		"PKCS8": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	}
	for name, privateKey := range keys {
		t.Run(name, func(t *testing.T) {
			store := &Bucket{bucket: "test-bucket", accessID: testAccessID, privateKey: privateKey}
			got, err := store.SignedURL(context.Background(), "npm/pkg/file.tgz", time.Minute)
			if err != nil {
				t.Fatalf("SignedURL failed: %v", err)
			}
			u := parseSignedURL(t, got)
			signature, err := base64.StdEncoding.DecodeString(u.Query().Get("Signature"))
			if err != nil {
				t.Fatalf("decoding signature: %v", err)
			}
			stringToSign := fmt.Sprintf("GET\n\n\n%s\n%s", u.Query().Get("Expires"), u.Path)
			digest := sha256.Sum256([]byte(stringToSign))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
				t.Fatalf("verifying signature: %v", err)
			}
		})
	}
}

func TestGCSSignedURLWithIAMSigner(t *testing.T) {
	signed := []byte("signed")
	store := &Bucket{
		bucket:   "test-bucket",
		accessID: testAccessID,
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPost || req.URL.Host != "iamcredentials.googleapis.com" {
				t.Fatalf("IAM request = %s %s", req.Method, req.URL.String())
			}
			var body struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decoding IAM request: %v", err)
			}
			payload, err := base64.StdEncoding.DecodeString(body.Payload)
			if err != nil || !strings.Contains(string(payload), "/test-bucket/npm/pkg/file.tgz") {
				t.Fatalf("IAM payload = %q, %v", payload, err)
			}
			response := `{"signedBlob":"` + base64.StdEncoding.EncodeToString(signed) + `"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(response)),
				Request:    req,
			}, nil
		})},
	}
	store.signBytes = store.signBlob

	got, err := store.SignedURL(context.Background(), "npm/pkg/file.tgz", time.Minute)
	if err != nil {
		t.Fatalf("SignedURL failed: %v", err)
	}
	u := parseSignedURL(t, got)
	if u.Query().Get("Signature") != base64.StdEncoding.EncodeToString(signed) {
		t.Fatalf("Signature = %q", u.Query().Get("Signature"))
	}
}

func parseSignedURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing signed URL: %v", err)
	}
	if u.Scheme != "https" || u.Host != "storage.googleapis.com" || u.Path != "/test-bucket/npm/pkg/file.tgz" {
		t.Fatalf("signed URL location = %s", rawURL)
	}
	if u.Query().Get("GoogleAccessId") != testAccessID {
		t.Fatalf("GoogleAccessId = %q", u.Query().Get("GoogleAccessId"))
	}
	return u
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func objectNameFromPath(p string) string {
	escaped := strings.TrimPrefix(p, "/storage/v1/b/test-bucket/o/")
	name, _ := url.PathUnescape(escaped)
	return name
}
