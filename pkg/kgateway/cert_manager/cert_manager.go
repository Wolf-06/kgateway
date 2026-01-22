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
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/xds"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/namespaces"
)

const (
	CertValidityDays = 3650 // 10 years
)

// NewCertWatcherWithBootstrap initializes the certificates and returns a watcher.
// It ensures the secret exists in K8s, writes it to the temp directory,
// and starts a background syncer to keep the temp directory updated.
func NewCertWatcherWithBootstrap(ctx context.Context, cli kube.Client, xdsServiceName string) (*certwatcher.CertWatcher, error) {
	// 1. Ensure K8s Secret Exists (API Call)
	certData, keyData, err := EnsureCertificateSecret(ctx, cli, xdsServiceName)
	if err != nil {
		return nil, fmt.Errorf("failed to bootstrap xDS TLS secret: %w", err)
	}

	// 2. Write to Temp Directory (Atomic Write)
	if err := InitializeCertificates(certData, keyData); err != nil {
		return nil, fmt.Errorf("failed to initialize temp certificates: %w", err)
	}

	// 3. Initialize Watcher
	// Now that files guaranteed exist, this will not fail.
	watcher, err := certwatcher.New(xds.TLSCertPath, xds.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create certwatcher: %w", err)
	}

	// 4. Start Background Volume Syncer
	// This ensures that when Kubelet updates the Volume mount (/etc/xds-tls),
	// we update our temp directory (/var/run/kgateway/xds-tls) so the watcher sees the new cert.
	go StartVolumeSyncer(ctx)

	slog.Info("successfully initialized xDS TLS system with bootstrap")
	return watcher, nil
}

// InitializeCertificates writes the provided cert/key to the temp directory using Atomic Writes.
func InitializeCertificates(certData, keyData []byte) error {
	// The directory /var/run/kgateway/xds-tls should be created by the emptyDir volume mount,
	// but we ensure it exists here for safety. MkdirAll is idempotent and won't fail if it exists.
	dir := filepath.Dir(xds.TLSCertPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to ensure temp dir exists for xDS TLS: %w", err)
	}

	if err := atomicWriteFile(xds.TLSCertPath, certData); err != nil {
		return fmt.Errorf("failed to write tls.crt: %w", err)
	}
	if err := atomicWriteFile(xds.TLSKeyPath, keyData); err != nil {
		return fmt.Errorf("failed to write tls.key: %w", err)
	}

	slog.Info("initialized xDS TLS certificates from API", "cert_path", xds.TLSCertPath, "key_path", xds.TLSKeyPath)
	return nil
}

// atomicWriteFile writes data to a temp file in the same directory and renames it.
// This prevents readers from seeing a partial file.
func atomicWriteFile(filename string, data []byte) error {
	dir := filepath.Dir(filename)

	// Create temp file in the SAME directory to ensure rename is atomic/possible
	tmpFile, err := os.CreateTemp(dir, "tls-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName) // Cleanup if rename fails

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmpName, 0600); err != nil {
		return err
	}

	return os.Rename(tmpName, filename)
}

const (
	// VolumeMountPath is where Kubernetes mounts the secret volume
	VolumeMountPath = "/etc/xds-tls"
	// SyncInterval is how often to check for volume updates
	SyncInterval = 10 * time.Second
)

// StartVolumeSyncer starts a background goroutine that syncs certificates from the volume mount to the temp directory.
func StartVolumeSyncer(ctx context.Context) {
	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	slog.Info("starting xDS TLS volume syncer", "mount_path", VolumeMountPath, "target_path", xds.TLSCertPath)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Sync only if source exists
			certSrc := filepath.Join(VolumeMountPath, "tls.crt")
			keySrc := filepath.Join(VolumeMountPath, "tls.key")

			if exists(certSrc) {
				if err := copyFileIfChanged(certSrc, xds.TLSCertPath); err != nil {
					slog.Error("failed to sync tls.crt", "error", err)
				}
			}
			if exists(keySrc) {
				if err := copyFileIfChanged(keySrc, xds.TLSKeyPath); err != nil {
					slog.Error("failed to sync tls.key", "error", err)
				}
			}
		}
	}
}

func exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// copyFileIfChanged copies src to dst only if the content differs.
// Uses atomicWriteFile for safety.
func copyFileIfChanged(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Read destination to compare
	if destData, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(sourceData, destData) {
			return nil // No change needed
		}
	}

	slog.Info("detected change in certificate volume, updating temp file", "file", dst)
	return atomicWriteFile(dst, sourceData)
}

func EnsureCertificateSecret(ctx context.Context, cli kube.Client, xdsServiceName string) (cert, key []byte, err error) {
	if xdsServiceName == "" {
		return nil, nil, fmt.Errorf("xdsServiceName cannot be empty")
	}

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
			// Handle race condition: if another pod created the secret between our Get and Create
			if apierrors.IsAlreadyExists(err) {
				slog.Info("xDS TLS secret was created by another process, fetching it", "secret", secretName, "namespace", namespace)
				existingSecret, getErr := cli.Kube().CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
				if getErr != nil {
					return nil, nil, fmt.Errorf("failed to get xDS TLS secret after AlreadyExists: %w", getErr)
				}
				return existingSecret.Data["tls.crt"], existingSecret.Data["tls.key"], nil
			}
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
	if certPEM == nil {
		return nil, nil, fmt.Errorf("failed to PEM encode CA certificate")
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if keyPEM == nil {
		return nil, nil, fmt.Errorf("failed to PEM encode CA private key")
	}

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
	if certPEM == nil {
		return nil, nil, fmt.Errorf("failed to PEM encode server certificate")
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if keyPEM == nil {
		return nil, nil, fmt.Errorf("failed to PEM encode server private key")
	}
	return certPEM, keyPEM, nil
}
