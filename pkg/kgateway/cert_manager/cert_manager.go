package certmanager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"istio.io/istio/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/xds"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/namespaces"
)

const (
	CertValidityDays = 3650 // 10 years
)

func EnsureCertificateSecret(ctx context.Context, cli kube.Client, xdsServiceName string) (cert, key []byte, err error) {
	namespace := namespaces.GetPodNamespace()
	secretName := xds.TLSSecretName

	//check if the secret already exists
	var isUpdate bool
	existingSecret, err := cli.Kube().CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil {
		isUpdate = true
		// Check if the certificate has expired
		if !isCertificateExpired(existingSecret.Data["tls.crt"]) {
			slog.Info("xDS TLS secret already exists and is valid, skipping generation", "secret", secretName, "namespace", namespace)
			return existingSecret.Data["tls.crt"], existingSecret.Data["tls.key"], nil
		}
		slog.Info("xDS TLS certificate has expired, regenerating", "secret", secretName, "namespace", namespace)
		// Fall through to regenerate
	} else if !apierrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("failed to check for existing secret: %w", err)
	}

	//generate a new certificate
	caCert, caKey, err := generateCA()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	serverCert, serverKey, err := generateServerCert(caCert, caKey, xdsServiceName, namespace)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	//create or update the secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kgateway",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": serverCert,
			"tls.key": serverKey,
			"ca.crt":  caCert,
		},
	}

	if isUpdate {
		// Update existing secret
		_, err = cli.Kube().CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update xDS TLS secret: %w", err)
		}
		slog.Info("successfully updated xDS TLS secret", "secret", secretName, "namespace", namespace)
	} else {
		// Create new secret
		_, err = cli.Kube().CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create xDS TLS secret: %w", err)
		}
		slog.Info("successfully created xDS TLS secret", "secret", secretName, "namespace", namespace)
	}

	return serverCert, serverKey, nil
}

// isCertificateExpired checks if the PEM-encoded certificate has expired.
func isCertificateExpired(certPEM []byte) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		slog.Warn("failed to decode PEM block, treating as expired")
		return true
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Warn("failed to parse certificate, treating as expired", "error", err)
		return true
	}

	// Consider expired if past NotAfter or within 7 days of expiration
	gracePeriod := 7 * 24 * time.Hour
	expirationThreshold := time.Now().Add(gracePeriod)

	if cert.NotAfter.Before(expirationThreshold) {
		slog.Info("certificate is expired or expiring soon", "not_after", cert.NotAfter, "threshold", expirationThreshold)
		return true
	}

	return false
}

// generateCA generates a CA certificate and private key
func generateCA() (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "kgateway-ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(CertValidityDays) * time.Hour * 24),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
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

// generateServerCert generates a server certificate using the provided CA certificate and private key
func generateServerCert(caCertPEM, caKeyPEM []byte, serviceName, namespace string) (certPEM, keyPEM []byte, err error) {
	//parse CA
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	//generate server key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	dnsNames := []string{
		serviceName,
		fmt.Sprintf("%s.%s", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc", serviceName, namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, namespace),
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serviceName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(CertValidityDays) * time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM, nil
}

const (
	// TempDir is the directory where certificates are written for the application to use
	TempDir = "/var/run/kgateway/xds-tls"
	// VolumeMountPath is where Kubernetes mounts the secret volume
	VolumeMountPath = "/etc/xds-tls"
	// SyncInterval is how often to check for volume updates
	SyncInterval = 15 * time.Second
)

// CertPaths holds the paths to the certificate and key files
type CertPaths struct {
	CertPath string
	KeyPath  string
}

// InitializeCertificates writes the provided cert/key to the temp directory and returns the paths.
// This is used to bootstrap TLS before the volume mount is available.
func InitializeCertificates(certData, keyData []byte) (*CertPaths, error) {
	if err := os.MkdirAll(TempDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create temp dir for xDS TLS: %w", err)
	}

	certPath := filepath.Join(TempDir, "tls.crt")
	keyPath := filepath.Join(TempDir, "tls.key")

	if err := os.WriteFile(certPath, certData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write tls.crt to temp dir: %w", err)
	}
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write tls.key to temp dir: %w", err)
	}

	slog.Info("initialized xDS TLS certificates from API", "cert_path", certPath, "key_path", keyPath)
	return &CertPaths{CertPath: certPath, KeyPath: keyPath}, nil
}

// StartVolumeSyncer starts a background goroutine that syncs certificates from the volume mount to the temp directory.
// This ensures that certificate rotations via Kubernetes secrets are picked up.
func StartVolumeSyncer(ctx context.Context, paths *CertPaths) {
	go func() {
		ticker := time.NewTicker(SyncInterval)
		defer ticker.Stop()
		slog.Info("starting xDS TLS volume syncer", "mount_path", VolumeMountPath, "target_path", TempDir)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mountCertPath := filepath.Join(VolumeMountPath, "tls.crt")
				mountKeyPath := filepath.Join(VolumeMountPath, "tls.key")

				// Only sync if the source file is non-empty.
				if stat, err := os.Stat(mountCertPath); err == nil && stat.Size() > 0 {
					if err := copyFileIfChanged(mountCertPath, paths.CertPath); err != nil {
						slog.Error("failed to sync xDS TLS cert from volume", "error", err)
					}
				}
				if stat, err := os.Stat(mountKeyPath); err == nil && stat.Size() > 0 {
					if err := copyFileIfChanged(mountKeyPath, paths.KeyPath); err != nil {
						slog.Error("failed to sync xDS TLS key from volume", "error", err)
					}
				}
			}
		}
	}()
}

// copyFileIfChanged copies src to dst only if the content differs.
func copyFileIfChanged(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	sourceData, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Check if destination exists and has same content
	if destData, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(sourceData, destData) {
			return nil // No change needed
		}
	}

	return os.WriteFile(dst, sourceData, 0600)
}
