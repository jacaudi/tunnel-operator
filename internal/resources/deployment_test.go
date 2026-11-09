package resources

import (
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

func testWireguard() *v1alpha1.Wireguard {
	return &v1alpha1.Wireguard{ObjectMeta: metav1.ObjectMeta{Name: "vpn", Namespace: "default"}}
}

func buildDeployment(t *testing.T, wg *v1alpha1.Wireguard) *appsv1.Deployment {
	t.Helper()
	dep, err := NewDeploymentBuilder(testScheme(t), "agent:test", corev1.PullIfNotPresent).ForWireguard(wg)
	if err != nil {
		t.Fatalf("ForWireguard: %v", err)
	}
	return dep
}

// containerNamed returns the container of the rendered pod called name.
func containerNamed(t *testing.T, dep *appsv1.Deployment, name string) corev1.Container {
	t.Helper()
	containers := dep.Spec.Template.Spec.Containers
	i := slices.IndexFunc(containers, func(c corev1.Container) bool { return c.Name == name })
	if i < 0 {
		t.Fatalf("containers = %v, want one named %s", containers, name)
	}
	return containers[i]
}

func TestAgentContainerPorts(t *testing.T) {
	agent := containerNamed(t, buildDeployment(t, testWireguard()), "agent")

	got := map[string]corev1.ContainerPort{}
	for _, p := range agent.Ports {
		got[p.Name] = p
	}
	want := map[string]corev1.ContainerPort{
		"wireguard":  {Name: "wireguard", ContainerPort: WireguardPort, Protocol: corev1.ProtocolUDP},
		"http":       {Name: "http", ContainerPort: HTTPPort, Protocol: corev1.ProtocolTCP},
		"egress-api": {Name: "egress-api", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
	}
	if !maps.Equal(got, want) {
		t.Errorf("agent ports = %v, want %v", got, want)
	}
}

func TestDeploymentMountsGluetunAuth(t *testing.T) {
	wg := testWireguard()
	dep := buildDeployment(t, wg)

	i := slices.IndexFunc(dep.Spec.Template.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == "gluetun-auth" })
	if i < 0 {
		t.Fatalf("volumes = %v, want one named gluetun-auth", dep.Spec.Template.Spec.Volumes)
	}
	wantVolume := corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
		SecretName: wg.Name,
		Items:      []corev1.KeyToPath{{Key: "gluetun-auth.toml", Path: "config.toml"}},
	}}
	if got := dep.Spec.Template.Spec.Volumes[i].VolumeSource; !reflect.DeepEqual(got, wantVolume) {
		t.Errorf("gluetun-auth volume = %+v, want %+v", got, wantVolume)
	}

	// A directory mount: a subPath mount would never see the file change.
	wantMount := corev1.VolumeMount{Name: "gluetun-auth", MountPath: "/gluetun/auth", ReadOnly: true}
	if got := containerNamed(t, dep, "gluetun").VolumeMounts; !reflect.DeepEqual(got, []corev1.VolumeMount{wantMount}) {
		t.Errorf("gluetun volume mounts = %+v, want [%+v]", got, wantMount)
	}
	// The agent reads the key from its env; it never needs gluetun's role file.
	for _, m := range containerNamed(t, dep, "agent").VolumeMounts {
		if m.Name == "gluetun-auth" {
			t.Errorf("agent mounts %+v, want no gluetun-auth", m)
		}
	}
}

func TestDeploymentAgentGetsAPIKey(t *testing.T) {
	wg := testWireguard()
	dep := buildDeployment(t, wg)

	want := corev1.EnvVar{Name: "GLUETUN_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: wg.Name},
		Key:                  "gluetun-api-key",
	}}}
	if got := containerNamed(t, dep, "agent").Env; !reflect.DeepEqual(got, []corev1.EnvVar{want}) {
		t.Errorf("agent env = %+v, want [%+v]", got, want)
	}
	for _, e := range containerNamed(t, dep, "gluetun").Env {
		if e.Name == "GLUETUN_API_KEY" {
			t.Errorf("gluetun env carries %s; only the agent gets the key", e.Name)
		}
	}
}

func TestDeploymentAlwaysEnablesIPForwardingAndReadsNoConfigMap(t *testing.T) {
	spec := buildDeployment(t, testWireguard()).Spec.Template.Spec

	if len(spec.InitContainers) != 1 || spec.InitContainers[0].Name != "sysctl" {
		t.Fatalf("init containers = %v, want exactly [sysctl]", spec.InitContainers)
	}
	sc := spec.InitContainers[0].SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Errorf("sysctl init container must be privileged, got %+v", sc)
	}

	agent := spec.Containers[0]
	if len(agent.EnvFrom) != 0 {
		t.Errorf("agent envFrom = %v, want none", agent.EnvFrom)
	}
	if slices.Contains(agent.Command, "--wg-use-userspace-implementation") {
		t.Errorf("agent command %v must not force the userspace implementation", agent.Command)
	}
}

func TestForWireguardRunsGluetunBesideTheAgent(t *testing.T) {
	wg := testWireguard()
	wg.Spec.LocalCIDRs = []string{"10.96.0.0/12"}
	wg.Spec.Gluetun = v1alpha1.GluetunSpec{
		Env: []corev1.EnvVar{{Name: "VPN_SERVICE_PROVIDER", Value: "custom"}},
		EnvFrom: []corev1.EnvFromSource{{
			SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "gluetun-creds"}},
		}},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
		},
	}
	dep := buildDeployment(t, wg)
	spec := dep.Spec.Template.Spec

	if got := containerNames(spec.Containers); !slices.Equal(got, []string{"agent", "gluetun"}) {
		t.Fatalf("container names = %v, want [agent gluetun]", got)
	}
	if got := containerNames(spec.InitContainers); !slices.Equal(got, []string{"sysctl"}) {
		t.Errorf("init container names = %v, want [sysctl]", got)
	}
	if got := dep.Spec.Strategy.Type; got != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("strategy type = %q, want %q", got, appsv1.RecreateDeploymentStrategyType)
	}

	agent, gluetun := spec.Containers[0], spec.Containers[1]
	if agent.ReadinessProbe == nil || agent.ReadinessProbe.TimeoutSeconds != 5 {
		t.Errorf("agent readiness probe = %+v, want TimeoutSeconds 5", agent.ReadinessProbe)
	}

	if gluetun.Image != GluetunImage {
		t.Errorf("gluetun image = %q, want %q", gluetun.Image, GluetunImage)
	}
	sc := gluetun.SecurityContext
	if sc == nil || sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Add, []corev1.Capability{"NET_ADMIN"}) {
		t.Errorf("gluetun security context = %+v, want exactly NET_ADMIN added", sc)
	} else if sc.ReadOnlyRootFilesystem != nil {
		t.Errorf("gluetun readOnlyRootFilesystem = %v, want unset: gluetun writes /gluetun and /tmp", *sc.ReadOnlyRootFilesystem)
	}
	wantEnv := append(ReservedGluetunEnv([]string{"10.96.0.0/12"}), corev1.EnvVar{Name: "VPN_SERVICE_PROVIDER", Value: "custom"})
	if !reflect.DeepEqual(gluetun.Env, wantEnv) {
		t.Errorf("gluetun env = %v, want %v", gluetun.Env, wantEnv)
	}
	if !reflect.DeepEqual(gluetun.EnvFrom, wg.Spec.Gluetun.EnvFrom) {
		t.Errorf("gluetun envFrom = %v, want %v", gluetun.EnvFrom, wg.Spec.Gluetun.EnvFrom)
	}
	if !reflect.DeepEqual(gluetun.Resources, wg.Spec.Gluetun.Resources) {
		t.Errorf("gluetun resources = %v, want %v", gluetun.Resources, wg.Spec.Gluetun.Resources)
	}
	wantHook := []string{"/bin/sh", "-c", "(ip rule del table 51820; ip -6 rule del table 51820) || true"}
	if gluetun.Lifecycle == nil || gluetun.Lifecycle.PostStart == nil || gluetun.Lifecycle.PostStart.Exec == nil ||
		!slices.Equal(gluetun.Lifecycle.PostStart.Exec.Command, wantHook) {
		t.Errorf("gluetun postStart = %+v, want exec %v", gluetun.Lifecycle, wantHook)
	}
	if gluetun.ReadinessProbe != nil || gluetun.LivenessProbe != nil || gluetun.StartupProbe != nil {
		t.Errorf("gluetun probes = %+v/%+v/%+v, want none", gluetun.ReadinessProbe, gluetun.LivenessProbe, gluetun.StartupProbe)
	}
}

func containerNames(cs []corev1.Container) []string {
	var names []string
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return names
}

// The component label marks the gateway pod so the injection policies skip it (a gateway pod's own
// traffic would loop through itself). It belongs on the pod template only: the selector is immutable,
// so adding to it would make every existing Deployment unapplyable.
func TestGatewayPodTemplateCarriesComponentLabelButSelectorDoesNot(t *testing.T) {
	dep := buildDeployment(t, testWireguard())

	if got := dep.Spec.Template.Labels[LabelComponent]; got != ComponentGateway {
		t.Errorf("pod template label %s = %q, want %q", LabelComponent, got, ComponentGateway)
	}
	if _, ok := dep.Spec.Selector.MatchLabels[LabelComponent]; ok {
		t.Errorf("selector = %v, want no %s", dep.Spec.Selector.MatchLabels, LabelComponent)
	}
	if _, ok := dep.Labels[LabelComponent]; ok {
		t.Errorf("deployment labels = %v, want no %s (the policies match pods, not Deployments)", dep.Labels, LabelComponent)
	}
}
