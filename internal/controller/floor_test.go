//go:build integration

package controllers

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/discovery"
)

// The operator's floor is Kubernetes 1.34 with the MutatingAdmissionPolicy beta enabled. This
// spec fails unless the envtest apiserver serves that beta, so the suite cannot pass on assets
// that predate it or on an apiserver started without the flags.
var _ = Describe("Kubernetes floor", func() {
	It("serves the MutatingAdmissionPolicy beta API", func() {
		const groupVersion = "admissionregistration.k8s.io/v1beta1"

		list, err := discovery.NewDiscoveryClientForConfigOrDie(cfg).ServerResourcesForGroupVersion(groupVersion)
		Expect(err).NotTo(HaveOccurred(), "discovery for %s", groupVersion)

		var served []string
		for _, r := range list.APIResources {
			served = append(served, r.Name)
		}
		Expect(served).To(ContainElements("mutatingadmissionpolicies", "mutatingadmissionpolicybindings"))
	})
})
