# EP-13294: xDS TLS Bootstrap for Certificate Management

* Issue: [#13294](https://github.com/kgateway-dev/kgateway/issues/13294)

## Background

The kgateway controller uses TLS for secure xDS communication with the gateway data planes. The current implementation relies on `certwatcher` from controller-runtime to watch TLS certificate files and automatically reload them when they change. However, this created a startup race condition where `certwatcher` expected certificate files to exist immediately, but the bootstrap controller that creates them runs asynchronously.

This EP proposes a "Smart Wrapper" pattern to ensure certificates are initialized synchronously before `certwatcher` starts, eliminating the race condition while maintaining support for dynamic certificate rotation.

## Motivation

In production deployments, when a new kgateway pod starts:
1. The `certwatcher` is initialized and expects certificate files at `/etc/xds-tls/`
2. The bootstrap controller attempts to create or fetch the TLS secret from Kubernetes
3. If the secret doesn't exist, the bootstrap controller generates new certificates
4. The certificates need to be written to temporary files for `certwatcher` to read

**The Problem**: These operations happen asynchronously, causing `certwatcher.New()` to fail if certificate files don't exist yet. This results in pod crashloops on first deployment.

**Additional Constraints**:
- The container runs as a non-root user
- The `/etc/xds-tls/` volume mount is read-only (mounted from K8s secret)
- We need a writable location for the initial certificate bootstrap

## Goals

- Eliminate the TLS certificate startup race condition
- Support both fresh deployments (secret doesn't exist) and existing deployments (secret exists)
- Maintain dynamic certificate rotation via `certwatcher`
- Support certificate updates from external sources (e.g., cert-manager)
- Work correctly with non-root container users
- Provide clear logging for debugging TLS initialization issues

## Non-Goals

- Replace `certwatcher` with a custom implementation
- Add mTLS support for client authentication (separate feature)
- Support custom certificate paths via configuration (can be added later)
- Change the certificate generation algorithm or validity period

## Implementation Details

### Architecture

The implementation uses a "Smart Wrapper" pattern with the following flow:

```
┌──────────────────────────────────────────────────────────────────┐
│                     Startup Sequence                              │
├──────────────────────────────────────────────────────────────────┤
│  1. EnsureCertificateSecret()                                     │
│     ├─→ If secret exists and valid: return cert/key data         │
│     └─→ If secret missing/expired: generate → create → return    │
│                                                                   │
│  2. InitializeCertificates()                                      │
│     └─→ Write cert/key to /tmp/kgateway-xds-tls/ atomically      │
│                                                                   │
│  3. certwatcher.New()                                             │
│     └─→ Initialize watcher with guaranteed-to-exist files        │
│                                                                   │
│  4. StartVolumeSyncer() [background]                              │
│     └─→ Sync /etc/xds-tls/ → /tmp/kgateway-xds-tls/              │
└──────────────────────────────────────────────────────────────────┘
```

### Configuration

**Environment Variables:**
- `KGW_XDS_TLS` (bool, default: `true`): Enable/disable xDS TLS
- `KGW_XDS_SERVICE_NAME` (string): The xDS service name for generating certificate DNS SANs

**Helm Values:**
```yaml
controller:
  xds:
    tls:
      enabled: true  # Enables the xDS TLS feature
```

### Certificate Manager Package

New package: `pkg/kgateway/cert_manager/cert_manager.go`

**Key Functions:**

1. **`NewCertWatcherWithBootstrap(ctx, client, xdsServiceName)`**
   - Main entry point for TLS initialization
   - Calls `EnsureCertificateSecret()` to get/create the K8s secret
   - Calls `InitializeCertificates()` to write files atomically
   - Initializes `certwatcher` with the temp file paths
   - Starts background volume syncer

2. **`EnsureCertificateSecret(ctx, client, xdsServiceName)`**
   - Checks if `kgateway-xds-cert` secret exists
   - If exists and not expired (7-day threshold): returns existing cert/key
   - If missing or expired: generates new CA and server certificate
   - Creates/updates the K8s secret with `tls.crt`, `tls.key`, `ca.crt`

3. **`InitializeCertificates(certData, keyData)`**
   - Ensures `/tmp/kgateway-xds-tls/` directory exists
   - Writes cert and key files atomically using temp file + rename pattern
   - Sets file permissions to `0600`

4. **`StartVolumeSyncer(ctx)`**
   - Background goroutine that syncs every 1 second
   - Copies `/etc/xds-tls/tls.crt` → `/tmp/kgateway-xds-tls/tls.crt`
   - Only copies if content differs (using byte comparison)
   - Logs certificate changes for debugging

### File Paths

| Purpose | Path | Source |
|---------|------|--------|
| K8s Secret Mount (read-only) | `/etc/xds-tls/` | Secret `kgateway-xds-cert` |
| Temp Files (writable) | `/tmp/kgateway-xds-tls/` | emptyDir volume |
| Cert Watcher Target | `/tmp/kgateway-xds-tls/tls.crt` | Written by InitializeCertificates |

**Why `/tmp/`?**  
The `/tmp` directory is writable by non-root users. Previous attempts to use `/var/run/kgateway/` failed because:
1. The parent directory doesn't exist
2. Non-root users cannot create directories in `/var/run/`

### Deployer (Helm Charts)

**kgateway deployment.yaml changes:**
```yaml
volumeMounts:
  - name: xds-tls
    mountPath: /etc/xds-tls
    readOnly: true
  - name: xds-tls-temp
    mountPath: /tmp/kgateway-xds-tls

volumes:
  - name: xds-tls
    secret:
      secretName: kgateway-xds-cert
      optional: true  # Allow pod to start before secret exists
  - name: xds-tls-temp
    emptyDir: {}
```

**agentgateway deployment.yaml changes:**
- Same volume mount structure as kgateway
- Fixed environment variable: `KGW_XDS_TLS_ENABLED` → `KGW_XDS_TLS`
- Added `optional: true` to secret volume

### Controllers

The `bootstrap` controller is extended to manage xDS TLS secrets:
- Added `xdsServiceName` parameter to `NewController()`
- Secret creation uses the service name for DNS SANs:
  - `{serviceName}.{namespace}.svc`
  - `{serviceName}.{namespace}.svc.cluster.local`

### Test Plan

**Unit Tests** (`pkg/kgateway/cert_manager/cert_manager_test.go`):
- `TestAtomicWriteFile` - Verifies atomic file writes with correct permissions
- `TestCopyFileIfChanged` - Verifies file sync with change detection
- `TestGenerateCA` - Verifies CA certificate generation
- `TestGenerateServerCert` - Verifies server certificate with correct DNS names
- `TestIsCertificateExpired` - Verifies certificate expiry detection
- `TestInitializeCertificates_HelperFunctions` - End-to-end file write verification

**Helm Golden File Tests** (`test/helm/`):
- Existing golden file tests updated to reflect new mount paths
- Tests for both kgateway and agentgateway charts

**E2E Tests**:
- Existing `TestKgateway` tests verify TLS is working end-to-end
- Pod startup is verified with TLS enabled by default

## Alternatives

### Alternative 1: Lazy Initialization in certwatcher
Instead of bootstrapping synchronously, modify the code to handle missing files gracefully and retry. This was rejected because:
- Adds complexity to handle edge cases
- Delays error detection to runtime
- Doesn't solve the "first secret" problem

### Alternative 2: Init Container
Use an init container to ensure certificates exist before the main container starts. This was rejected because:
- Adds operational complexity
- Requires additional RBAC for init container
- Increases pod startup time

### Alternative 3: Use /var/run with elevated privileges
Run the container as root to write to `/var/run/kgateway/`. This was rejected because:
- Security anti-pattern
- Violates principle of least privilege
- May conflict with Pod Security Standards

## Open Questions

1. **Certificate Rotation Policy**: Should we expose configuration for the certificate validity period (currently 1 year with 7-day renewal threshold)?

2. **External Certificate Integration**: How should we handle users who want to bring their own certificates via cert-manager or similar tools?

3. **Multiple Replicas**: When multiple kgateway pods start simultaneously, they may race to create the secret. The current implementation handles this with `IsAlreadyExists` error handling, but should we add distributed locking?
