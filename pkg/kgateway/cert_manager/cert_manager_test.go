package certmanager

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate() (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(8 * 24 * time.Hour), // 8 days to be beyond 7-day threshold
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

func TestAtomicWriteFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testData := []byte("test data")

	// Test: Write file atomically
	err := atomicWriteFile(testFile, testData)
	require.NoError(t, err)

	// Verify file exists and has correct content
	data, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, testData, data)

	// Verify file permissions
	info, err := os.Stat(testFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Test: Overwrite existing file
	newData := []byte("new test data")
	err = atomicWriteFile(testFile, newData)
	require.NoError(t, err)

	data, err = os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, newData, data)
}

func TestAtomicWriteFile_DirectoryNotExist(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "nonexistent", "test.txt")
	testData := []byte("test data")

	// This should fail because the directory doesn't exist
	err := atomicWriteFile(testFile, testData)
	assert.Error(t, err)
}

func TestCopyFileIfChanged(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "source.txt")
	dstFile := filepath.Join(tempDir, "dest.txt")

	testData := []byte("test data")
	err := os.WriteFile(srcFile, testData, 0600)
	require.NoError(t, err)

	// Test: Copy when destination doesn't exist
	err = copyFileIfChanged(srcFile, dstFile)
	require.NoError(t, err)

	// Verify destination has correct content
	dstData, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, testData, dstData)

	// Test: No copy when files are identical (should return nil)
	err = copyFileIfChanged(srcFile, dstFile)
	require.NoError(t, err)

	// Test: Copy when source changes
	newData := []byte("new test data")
	err = os.WriteFile(srcFile, newData, 0600)
	require.NoError(t, err)

	err = copyFileIfChanged(srcFile, dstFile)
	require.NoError(t, err)

	// Verify destination updated
	dstData, err = os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, newData, dstData)
}

func TestCopyFileIfChanged_SourceNotExist(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "nonexistent.txt")
	dstFile := filepath.Join(tempDir, "dest.txt")

	err := copyFileIfChanged(srcFile, dstFile)
	assert.Error(t, err)
}

func TestGenerateCA(t *testing.T) {
	caCert, caKey, err := generateCA()
	require.NoError(t, err)
	assert.NotEmpty(t, caCert)
	assert.NotEmpty(t, caKey)

	// Verify it's valid PEM
	block, _ := pem.Decode(caCert)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	keyBlock, _ := pem.Decode(caKey)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)

	// Verify it's a valid certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	assert.Equal(t, "kgateway-ca", cert.Subject.CommonName)
}

func TestGenerateServerCert(t *testing.T) {
	// Generate CA first
	caCert, caKey, err := generateCA()
	require.NoError(t, err)

	// Test: Generate server certificate
	serverCert, serverKey, err := generateServerCert(caCert, caKey, "test-service", "test-namespace")
	require.NoError(t, err)
	assert.NotEmpty(t, serverCert)
	assert.NotEmpty(t, serverKey)

	// Verify it's valid PEM
	block, _ := pem.Decode(serverCert)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	keyBlock, _ := pem.Decode(serverKey)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)

	// Verify it's a valid certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.False(t, cert.IsCA)
	assert.Contains(t, cert.DNSNames, "test-service.test-namespace.svc")
	assert.Contains(t, cert.DNSNames, "test-service.test-namespace.svc.cluster.local")
}

func TestIsCertificateExpired(t *testing.T) {
	// Test: Valid certificate (not expired)
	certPEM, _, err := generateTestCertificate()
	require.NoError(t, err)

	expired := isCertificateExpired(certPEM)
	assert.False(t, expired)

	// Test: Invalid PEM
	expired = isCertificateExpired([]byte("invalid pem"))
	assert.True(t, expired)

	// Test: Empty data
	expired = isCertificateExpired([]byte{})
	assert.True(t, expired)
}

func TestIsCertificateExpired_ExpiredCert(t *testing.T) {
	// Generate an expired certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "expired.example.com",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	expired := isCertificateExpired(certPEM)
	assert.True(t, expired)
}

func TestInitializeCertificates_HelperFunctions(t *testing.T) {
	// Test the helper functions used by InitializeCertificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "tls.crt")
	keyPath := filepath.Join(tempDir, "tls.key")

	certPEM, keyPEM, err := generateTestCertificate()
	require.NoError(t, err)

	// Test atomicWriteFile (used by InitializeCertificates)
	err = atomicWriteFile(certPath, certPEM)
	require.NoError(t, err)
	err = atomicWriteFile(keyPath, keyPEM)
	require.NoError(t, err)

	// Verify files exist and have correct content
	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(certPEM, certData))

	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(keyPEM, keyData))

	// Verify file permissions
	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
}
