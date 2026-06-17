package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClient_Default(t *testing.T) {
	client, err := NewHTTPClient(TLSOptions{})
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "transport should be *http.Transport")
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
	assert.Equal(t, 30*time.Second, transport.ResponseHeaderTimeout)
	assert.Nil(t, transport.TLSClientConfig.RootCAs, "default should use system CA pool")
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewHTTPClient_Insecure(t *testing.T) {
	// Capture stderr warning
	client, err := NewHTTPClient(TLSOptions{Insecure: true})
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewHTTPClient_CACert(t *testing.T) {
	// Generate a self-signed CA cert for testing.
	certPath := generateTestCA(t)

	client, err := NewHTTPClient(TLSOptions{CACertPath: certPath})
	require.NoError(t, err)
	require.NotNil(t, client)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs, "should have custom CA pool")
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestNewHTTPClient_CACertNotFound(t *testing.T) {
	_, err := NewHTTPClient(TLSOptions{CACertPath: "/nonexistent/ca.pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read CA certificate file")
}

func TestNewHTTPClient_CACertInvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	badCert := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(badCert, []byte("not a PEM certificate"), 0o600))

	_, err := NewHTTPClient(TLSOptions{CACertPath: badCert})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid PEM certificates")
}

func TestNewHTTPClient_InsecureConnectsToSelfSigned(t *testing.T) {
	// Start a TLS server with a self-signed cert.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Default client should fail (self-signed cert).
	defaultClient, err := NewHTTPClient(TLSOptions{})
	require.NoError(t, err)
	req1, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)
	_, err = defaultClient.Do(req1) //nolint:bodyclose,gosec // error path; httptest URL is not user-tainted
	require.Error(t, err, "default client should reject self-signed cert")

	// Insecure client should succeed.
	insecureClient, err := NewHTTPClient(TLSOptions{Insecure: true})
	require.NoError(t, err)
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := insecureClient.Do(req2) //nolint:gosec // httptest URL is not user-tainted
	require.NoError(t, err, "insecure client should accept self-signed cert")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestNewHTTPClient_CACertConnectsToCustomCA(t *testing.T) {
	// Generate a CA and server cert.
	caKey, caCert := generateTestCAPair(t)
	serverCert := generateServerCert(t, caKey, caCert)

	// Write CA cert to file.
	caCertPath := filepath.Join(t.TempDir(), "ca.pem")
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	require.NoError(t, os.WriteFile(caCertPath, caCertPEM, 0o600))

	// Start TLS server with the signed cert.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// Default client should fail (unknown CA).
	defaultClient, err := NewHTTPClient(TLSOptions{})
	require.NoError(t, err)
	req1, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)
	_, err = defaultClient.Do(req1) //nolint:bodyclose,gosec // error path; httptest URL is not user-tainted
	require.Error(t, err, "default client should reject unknown CA")

	// Client with custom CA should succeed.
	caClient, err := NewHTTPClient(TLSOptions{CACertPath: caCertPath})
	require.NoError(t, err)
	req2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := caClient.Do(req2) //nolint:gosec // httptest URL is not user-tainted
	require.NoError(t, err, "client with custom CA should accept server cert")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestNewHTTPClient_MinTLS12(t *testing.T) {
	client, err := NewHTTPClient(TLSOptions{})
	require.NoError(t, err)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

func TestValidateAndBuildAPIURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		path    string
		wantErr bool
	}{
		{"https valid", "https://example.com", "/api/v1", false},
		{"http valid", "http://example.com", "/api/v1", false},
		{"ftp invalid", "ftp://example.com", "/api/v1", true},
		{"no scheme", "example.com", "/api/v1", true},
		{"empty", "", "/api/v1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ValidateAndBuildAPIURL(tt.rawURL, tt.path, "Test")
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.path, u.Path)
			}
		})
	}
}

// --- Test helpers ---

// generateTestCA writes a self-signed CA cert PEM to a temp file and returns the path.
func generateTestCA(t *testing.T) string {
	t.Helper()
	_, cert := generateTestCAPair(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	require.NoError(t, os.WriteFile(path, certPEM, 0o600))
	return path
}

// generateTestCAPair creates a CA private key and self-signed certificate.
func generateTestCAPair(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return key, cert
}

// generateServerCert creates a TLS server certificate signed by the given CA.
func generateServerCert(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) tls.Certificate {
	t.Helper()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Server"}},
		DNSNames:     []string{"127.0.0.1", "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverKey,
		Leaf:        cert,
	}
}

func TestReadLimitedBody(t *testing.T) {
	t.Run("reads body within limit", func(t *testing.T) {
		body, err := ReadLimitedBody(strings.NewReader("hello"), 100)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(body))
	})

	t.Run("reads body at exact limit", func(t *testing.T) {
		data := strings.Repeat("x", 100)
		body, err := ReadLimitedBody(strings.NewReader(data), 100)
		require.NoError(t, err)
		assert.Len(t, body, 100)
	})

	t.Run("rejects body exceeding limit", func(t *testing.T) {
		data := strings.Repeat("x", 101)
		_, err := ReadLimitedBody(strings.NewReader(data), 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeded")
	})
}
