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

package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"os"

	vpnv1alpha1 "github.com/jacaudi/tunnel-operator/api/v1alpha1"
	controllers "github.com/jacaudi/tunnel-operator/internal/controller"
	v1 "k8s.io/api/core/v1"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(vpnv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

// operatorNamespace returns the namespace the operator runs in, which the Deployment supplies through the
// downward API. It is the one namespace whose default-gateway annotation the operator honours, so a
// missing value is a startup error rather than a guess.
func operatorNamespace() (string, error) {
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		return "", errors.New("POD_NAMESPACE is required: the operator selects the default gateway from its own namespace")
	}
	return ns, nil
}

func main() {
	var agentImagePullPolicy string
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var wgImage string
	var leaderElectionNamespaceFlag string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&wgImage, "agent-image", "", "The image used for wireguard server")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&agentImagePullPolicy, "agent-image-pull-policy", "IfNotPresent", "The image pull policy for the agent container")
	flag.StringVar(&leaderElectionNamespaceFlag, "leader-election-namespace", "", "Namespace to place the leader election Lease. Defaults to the operator Pod's namespace when empty.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	podNamespace, err := operatorNamespace()
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	leaderElectionNamespace := cmp.Or(leaderElectionNamespaceFlag, podNamespace)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:    metricsAddr,
			FilterProvider: metricsfilters.WithAuthenticationAndAuthorization,
		},
		Cache:                   controllers.CacheOptions(),
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "a6d3bffc.wireguard-operator.io",
		LeaderElectionNamespace: leaderElectionNamespace,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if wgImage == "" {
		setupLog.Error(fmt.Errorf("--agent-image flag is not set"), "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.WireguardReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		AgentImage:           wgImage,
		AgentImagePullPolicy: v1.PullPolicy(agentImagePullPolicy),
		APIReader:            mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Wireguard")
		os.Exit(1)
	}

	if err = (&controllers.ClientRoleBindingReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClientRoleBinding")
		os.Exit(1)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create discovery client")
		os.Exit(1)
	}
	if err = (&controllers.InjectionPolicyReconciler{
		Client:            mgr.GetClient(),
		Discovery:         discoveryClient,
		Image:             wgImage,
		OperatorNamespace: podNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "InjectionPolicy")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
