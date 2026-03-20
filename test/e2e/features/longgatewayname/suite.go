//go:build e2e

package longgatewayname

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/pkg/utils/fsutils"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/requestutils/curl"
	"github.com/kgateway-dev/kgateway/v2/test/e2e"
	"github.com/kgateway-dev/kgateway/v2/test/e2e/common"
	testdefaults "github.com/kgateway-dev/kgateway/v2/test/e2e/defaults"
	"github.com/kgateway-dev/kgateway/v2/test/e2e/tests/base"
	testmatchers "github.com/kgateway-dev/kgateway/v2/test/gomega/matchers"
)

var _ e2e.NewSuiteFunc = NewTestingSuite

const (
	longGatewayName          = "very-long-gateway-name-to-verify-routing-behavior-still-works-much-more-longer"
	longRouteName            = "long-example-route"
	samePrefixGatewayNameOne = "very-long-gateway-name-to-verify-routing-behavior-same-prefix-aaaaaaaaaaaaaaaaa-one"
	samePrefixGatewayNameTwo = "very-long-gateway-name-to-verify-routing-behavior-same-prefix-aaaaaaaaaaaaaaaaa-two"
	samePrefixRouteNameOne   = "long-example-route-a"
	samePrefixRouteNameTwo   = "long-example-route-b"
)

var (
	setupManifest      = filepath.Join(fsutils.MustGetThisDir(), "testdata", "gateway-with-long-name.yaml")
	samePrefixManifest = filepath.Join(fsutils.MustGetThisDir(), "testdata", "gateway-with-same-prefix-long-names.yaml")
	serviceManifest    = filepath.Join(fsutils.MustGetThisDir(), "testdata", "service.yaml")

	setup     = base.TestCase{Manifests: []string{serviceManifest, setupManifest}}
	testCases = map[string]*base.TestCase{
		"TestLongGatewayNameRouting":               {},
		"TestSamePrefixMultipleGatewayNameRouting": {Manifests: []string{samePrefixManifest}},
	}
)

type testingSuite struct {
	*base.BaseTestingSuite
	longGateway common.Gateway
}

func NewTestingSuite(ctx context.Context, testInst *e2e.TestInstallation) suite.TestingSuite {
	return &testingSuite{
		BaseTestingSuite: base.NewBaseTestingSuite(ctx, testInst, setup, testCases),
	}
}

func (s *testingSuite) SetupSuite() {
	s.BaseTestingSuite.SetupSuite()
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx,
		"default",
		metav1.ListOptions{LabelSelector: testdefaults.WellKnownAppLabel + "=" + safeGatewayName(longGatewayName)},
		time.Second*120,
		time.Millisecond*500,
	)
	address := s.TestInstallation.Assertions.EventuallyGatewayAddress(s.Ctx, longGatewayName, "default")
	s.longGateway = common.Gateway{
		NamespacedName: types.NamespacedName{Name: longGatewayName, Namespace: "default"},
		Address:        address,
	}
}

func safeGatewayName(name string) string {
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(sum[:])[:12]
	prefix := strings.TrimSuffix(name[:50], "-")
	return prefix + "-" + hash
}

func (s *testingSuite) TestLongGatewayNameRouting() {
	s.TestInstallation.AssertionsT(s.T()).EventuallyGatewayCondition(
		s.Ctx,
		longGatewayName,
		"default",
		gwv1.GatewayConditionProgrammed,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		longRouteName,
		"default",
		gwv1.RouteConditionAccepted,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		longRouteName,
		"default",
		gwv1.RouteConditionResolvedRefs,
		metav1.ConditionTrue,
	)
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx,
		"default",
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=long-nginx"},
		time.Second*120,
		time.Millisecond*500,
	)

	// --- NEW CODE: Wait for Envoy Data Plane to physically bind port 8080 ---
	s.T().Logf("Waiting for Envoy data plane to bind port 8080 at %s...", s.longGateway.Address)
	gomega.Eventually(func() error {
		addr := s.longGateway.Address
		if _, _, err := net.SplitHostPort(addr); err != nil {
			// addr does not include a valid port; assume it's just a host and add the default port.
			addr = net.JoinHostPort(addr, "8080")
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}, time.Second*60, time.Second*2).Should(gomega.Succeed(), "Timeout waiting for Envoy data plane to open port 8080")
	// ------------------------------------------------------------------------

	s.longGateway.Send(
		s.T(),
		&testmatchers.HttpResponse{
			StatusCode: http.StatusOK,
			Body:       gomega.ContainSubstring(testdefaults.NginxResponse),
		},
		curl.WithHostHeader("long.example.com"),
		curl.WithPort(8080), // <-- Bring this back! Since KinD uses raw IPs, we need to enforce the port here.
	)
}

func (s *testingSuite) TestSamePrefixMultipleGatewayNameRouting() {
	s.Require().NotEqual(safeGatewayName(samePrefixGatewayNameOne), safeGatewayName(samePrefixGatewayNameTwo))

	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx,
		"default",
		metav1.ListOptions{LabelSelector: testdefaults.WellKnownAppLabel + "=" + safeGatewayName(samePrefixGatewayNameOne)},
		time.Second*120,
		time.Millisecond*500,
	)
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx,
		"default",
		metav1.ListOptions{LabelSelector: testdefaults.WellKnownAppLabel + "=" + safeGatewayName(samePrefixGatewayNameTwo)},
		time.Second*120,
		time.Millisecond*500,
	)

	s.TestInstallation.AssertionsT(s.T()).EventuallyGatewayCondition(
		s.Ctx,
		samePrefixGatewayNameOne,
		"default",
		gwv1.GatewayConditionProgrammed,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyGatewayCondition(
		s.Ctx,
		samePrefixGatewayNameTwo,
		"default",
		gwv1.GatewayConditionProgrammed,
		metav1.ConditionTrue,
	)

	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		samePrefixRouteNameOne,
		"default",
		gwv1.RouteConditionAccepted,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		samePrefixRouteNameOne,
		"default",
		gwv1.RouteConditionResolvedRefs,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		samePrefixRouteNameTwo,
		"default",
		gwv1.RouteConditionAccepted,
		metav1.ConditionTrue,
	)
	s.TestInstallation.AssertionsT(s.T()).EventuallyHTTPRouteCondition(
		s.Ctx,
		samePrefixRouteNameTwo,
		"default",
		gwv1.RouteConditionResolvedRefs,
		metav1.ConditionTrue,
	)

	firstGateway := common.Gateway{
		NamespacedName: types.NamespacedName{Name: samePrefixGatewayNameOne, Namespace: "default"},
		Address:        s.TestInstallation.Assertions.EventuallyGatewayAddress(s.Ctx, samePrefixGatewayNameOne, "default"),
	}
	secondGateway := common.Gateway{
		NamespacedName: types.NamespacedName{Name: samePrefixGatewayNameTwo, Namespace: "default"},
		Address:        s.TestInstallation.Assertions.EventuallyGatewayAddress(s.Ctx, samePrefixGatewayNameTwo, "default"),
	}

	firstGateway.Send(
		s.T(),
		&testmatchers.HttpResponse{
			StatusCode: http.StatusOK,
			Body:       gomega.ContainSubstring(testdefaults.NginxResponse),
		},
		curl.WithHostHeader("long-a.example.com"),
		curl.WithPort(8080),
	)
	secondGateway.Send(
		s.T(),
		&testmatchers.HttpResponse{
			StatusCode: http.StatusOK,
			Body:       gomega.ContainSubstring(testdefaults.NginxResponse),
		},
		curl.WithHostHeader("long-b.example.com"),
		curl.WithPort(8080),
	)
}
