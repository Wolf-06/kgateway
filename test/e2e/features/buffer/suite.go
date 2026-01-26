//go:build e2e

package buffer

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/pkg/utils/fsutils"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/requestutils/curl"
	"github.com/kgateway-dev/kgateway/v2/test/e2e"
	testdefaults "github.com/kgateway-dev/kgateway/v2/test/e2e/defaults"
	"github.com/kgateway-dev/kgateway/v2/test/e2e/tests/base"
)

var _ e2e.NewSuiteFunc = NewTestingSuite

type testingSuite struct {
	*base.BaseTestingSuite
}

var (
	setupManifest = filepath.Join(fsutils.MustGetThisDir(), "testdata", "setup.yaml")

	testCases = map[string]*base.TestCase{
		"TestBufferLimit": {
			Manifests: []string{
				testdefaults.HttpbinManifest,
				setupManifest,
			},
		},
	}
)

func NewTestingSuite(ctx context.Context, testInst *e2e.TestInstallation) suite.TestingSuite {
	return &testingSuite{
		BaseTestingSuite: base.NewBaseTestingSuite(ctx, testInst, base.TestCase{}, testCases),
	}
}

func (s *testingSuite) TestBufferLimit() {
	// Wait for HTTPRoute to be accepted
	s.TestInstallation.Assertions.EventuallyHTTPRouteCondition(
		s.Ctx,
		"test-route",
		"default",
		gwv1.RouteConditionAccepted,
		metav1.ConditionTrue,
	)

	// Get gateway address
	gatewayAddress := s.TestInstallation.Assertions.EventuallyGatewayAddress(
		s.Ctx,
		"test-gateway",
		"default",
	)

	// Case 1: Request size within limit (500 bytes < 1Ki) - should succeed
	gomega.Eventually(func(g gomega.Gomega) {
		resp, err := curl.ExecuteRequest(
			curl.WithHost(gatewayAddress),
			curl.WithPort(8080),
			curl.WithPath("/post"),
			curl.WithMethod("POST"),
			curl.WithBody(strings.Repeat("a", 500)),
			curl.WithConnectionTimeout(5),
		)
		g.Expect(err).NotTo(gomega.HaveOccurred())
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	}).WithTimeout(60 * time.Second).WithPolling(1 * time.Second).Should(gomega.Succeed())

	// Case 2: Request size exceeds limit (2000 bytes > 1Ki) - should return 413
	gomega.Eventually(func(g gomega.Gomega) {
		resp, err := curl.ExecuteRequest(
			curl.WithHost(gatewayAddress),
			curl.WithPort(8080),
			curl.WithPath("/post"),
			curl.WithMethod("POST"),
			curl.WithBody(strings.Repeat("a", 2000)),
			curl.WithConnectionTimeout(5),
		)
		g.Expect(err).NotTo(gomega.HaveOccurred())
		defer resp.Body.Close()
		// Read body to ensure connection is properly handled
		_, _ = io.ReadAll(resp.Body)
		g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusRequestEntityTooLarge))
	}).WithTimeout(60 * time.Second).WithPolling(1 * time.Second).Should(gomega.Succeed())
}
