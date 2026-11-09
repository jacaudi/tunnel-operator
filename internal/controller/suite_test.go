//go:build integration

/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	vpnv1alpha1 "github.com/jacaudi/tunnel-operator/api/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var k8sClient client.Client
var writeCounter *countingClient

// egressReader is the reconciler's EgressReader: specs set what each pod IP reports.
var egressReader = newFakeEgressReader()

var testEnv *envtest.Environment
var wgTestImage = "test-image"

// cfg is the rest config of the envtest apiserver, shared with specs that talk to it directly.
var cfg *rest.Config

// testLocalCIDRs is a valid spec.localCIDRs for envtest: its apiserver allocates ClusterIPs from
// 10.0.0.0/24 (controller-runtime's envtest default), and the range overlaps no peerCIDR a spec uses.
var testLocalCIDRs = []string{"10.0.0.0/24"}

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t,
		"Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:       []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing:   true,
		ControlPlaneStopTimeout: time.Second * 120,
	}

	// The operator's floor is Kubernetes 1.34 with the MutatingAdmissionPolicy beta enabled.
	testEnv.ControlPlane.GetAPIServer().Configure().
		Append("feature-gates", "MutatingAdmissionPolicy=true").
		Append("runtime-config", "admissionregistration.k8s.io/v1beta1=true")

	if os.Getenv("ENVTEST_DEBUG_OUTPUT") != "" {
		testEnv.ControlPlane.GetAPIServer().Out = GinkgoWriter
		testEnv.ControlPlane.GetAPIServer().Err = GinkgoWriter
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = vpnv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	By("installing the static admission backstop")
	installAdmissionBackstop()
	waitForBackstop()

	// The manager caches only labelled pods, as in cmd/manager: any reader of Pods through the cache sees
	// nothing else, so a spec that reads an unlabelled pod through it fails here as it would in a cluster.
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		Cache:  CacheOptions(),
	})
	Expect(err).ToNot(HaveOccurred())

	writeCounter = newCountingClient(k8sManager.GetClient())

	err = (&WireguardReconciler{
		Client:               writeCounter,
		Scheme:               k8sManager.GetScheme(),
		AgentImagePullPolicy: "IfNotPresent",
		AgentImage:           wgTestImage,
		APIReader:            k8sManager.GetAPIReader(),
		EgressReader:         egressReader,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	// The operator's own namespace is wg-system: only a Wireguard there can be the default gateway.
	err = (&InjectionPolicyReconciler{
		Client:            k8sManager.GetClient(),
		Discovery:         discovery.NewDiscoveryClientForConfigOrDie(cfg),
		Image:             wgTestImage,
		OperatorNamespace: testOperatorNamespace,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	// The client RoleBinding reconciler runs on a manager of its own, so a spec can stop it (the operator is
	// down) and start another.
	stopRoleBindings = startRoleBindingManager()

	// envtest runs no kube-controller-manager; fakeRollout reports the operator's Deployments rolled out.
	err = ctrl.NewControllerManagedBy(k8sManager).
		Named("fake-rollout").
		For(&appsv1.Deployment{}).
		Complete(&fakeRollout{Client: k8sManager.GetClient()})
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()

}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	stopRoleBindings()
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
