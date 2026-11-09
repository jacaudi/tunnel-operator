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

package resources

import (
	"fmt"
	"maps"

	"github.com/jacaudi/tunnel-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// HTTPPort is the port for HTTP health checks.
	HTTPPort = 8080

	// UserspaceImplementation is the userspace WireGuard binary the agent starts when the kernel module
	// is unavailable.
	UserspaceImplementation = "wireguard-go"
)

// DeploymentBuilder builds deployments for wireguard resources.
type DeploymentBuilder struct {
	scheme               *runtime.Scheme
	agentImage           string
	agentImagePullPolicy corev1.PullPolicy
}

// NewDeploymentBuilder creates a new DeploymentBuilder.
func NewDeploymentBuilder(scheme *runtime.Scheme, agentImage string, agentImagePullPolicy corev1.PullPolicy) *DeploymentBuilder {
	return &DeploymentBuilder{
		scheme:               scheme,
		agentImage:           agentImage,
		agentImagePullPolicy: agentImagePullPolicy,
	}
}

// ForWireguard creates a deployment for a Wireguard server.
func (b *DeploymentBuilder) ForWireguard(wg *v1alpha1.Wireguard) (*appsv1.Deployment, error) {
	ls := LabelsForWireguard(wg.Name)
	podLabels := maps.Clone(ls)
	podLabels[LabelComponent] = ComponentGateway
	replicas := int32(1)

	// Security context settings
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := false
	automountServiceAccountToken := false

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      wg.Name + "-dep",
			Namespace: wg.Namespace,
			Labels:    ls,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			// One replica owns the WireGuard key and the tunnel, so the old pod must be gone before the
			// new one starts.
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					// Not in the selector, which is immutable; see LabelComponent.
					Labels: podLabels,
				},
				Spec: corev1.PodSpec{
					NodeSelector: wg.Spec.NodeSelector,
					Tolerations:  wg.Spec.Tolerations,
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileType("RuntimeDefault"),
						},
					},
					AutomountServiceAccountToken: &automountServiceAccountToken,
					Volumes: []corev1.Volume{
						{
							Name: "socket",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: wg.Name,
								},
							},
						},
						{
							// Only the roles file: the Secret's other keys are the agent's, not gluetun's.
							Name: gluetunAuthVolume,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: wg.Name,
									Items:      []corev1.KeyToPath{{Key: SecretKeyGluetunAuth, Path: gluetunAuthFile}},
								},
							},
						},
					},
					InitContainers: []corev1.Container{b.ipForwardInitContainer()},
					Containers: []corev1.Container{
						b.agentContainer(wg, readOnlyRootFilesystem, allowPrivilegeEscalation),
						b.gluetunContainer(wg),
					},
				},
			},
		},
	}

	if err := SetOwnerReference(wg, dep, b.scheme); err != nil {
		return nil, err
	}

	return dep, nil
}

// agentContainer creates the agent container for the deployment.
func (b *DeploymentBuilder) agentContainer(wg *v1alpha1.Wireguard, readOnlyRootFilesystem, allowPrivilegeEscalation bool) corev1.Container {
	return corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
		},
		Image:           b.agentImage,
		ImagePullPolicy: b.agentImagePullPolicy,
		Name:            "agent",
		Command: []string{
			"agent",
			"--v", "11",
			"--wg-iface", WgInterface,
			"--wg-listen-port", fmt.Sprintf("%d", WireguardPort),
			"--state", "/tmp/wireguard/state.json",
			"--wg-userspace-implementation-fallback", UserspaceImplementation,
		},
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: WireguardPort,
				Name:          "wireguard",
				Protocol:      corev1.ProtocolUDP,
			},
			{
				ContainerPort: HTTPPort,
				Name:          "http",
				Protocol:      corev1.ProtocolTCP,
			},
			{
				ContainerPort: EgressAPIPort,
				Name:          "egress-api",
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Env: []corev1.EnvVar{{
			Name: EnvGluetunAPIKey,
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: wg.Name},
				Key:                  SecretKeyGluetunAPIKey,
			}},
		}},
		ReadinessProbe: &corev1.Probe{
			// /health syncs wg0 and polls gluetun's health server; the 1 s default is too short for both.
			TimeoutSeconds: 5,
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Port: intstr.FromInt32(HTTPPort),
					Path: "/health",
				},
			},
		},
		LivenessProbe: &corev1.Probe{
			PeriodSeconds: 5,
			ProbeHandler: corev1.ProbeHandler{
				TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.FromInt32(HTTPPort),
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "socket",
				MountPath: "/var/run/wireguard/",
			},
			{
				Name:      "config",
				MountPath: "/tmp/wireguard/",
			},
		},
		Resources: wg.Spec.Agent.Resources,
	}
}

// gluetunContainer creates the gluetun container, which gives the pod its tunnel to the VPN provider.
// It shares the agent's network namespace.
func (b *DeploymentBuilder) gluetunContainer(wg *v1alpha1.Wireguard) corev1.Container {
	return corev1.Container{
		Name:  "gluetun",
		Image: GluetunImage,
		// gluetun writes /gluetun and /tmp, so the root filesystem stays writable.
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
		},
		Env:       append(ReservedGluetunEnv(wg.Spec.LocalCIDRs), wg.Spec.Gluetun.Env...),
		EnvFrom:   wg.Spec.Gluetun.EnvFrom,
		Resources: wg.Spec.Gluetun.Resources,
		VolumeMounts: []corev1.VolumeMount{
			// A directory mount, not a subPath: a subPath never sees the Secret change.
			{Name: gluetunAuthVolume, MountPath: gluetunAuthDir, ReadOnly: true},
		},
		Lifecycle: &corev1.Lifecycle{
			PostStart: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/bin/sh", "-c",
						fmt.Sprintf("(ip rule del table %d; ip -6 rule del table %d) || true", gluetunRuleTable, gluetunRuleTable),
					},
				},
			},
		},
	}
}

// ipForwardInitContainer creates an init container to enable IP forwarding.
func (b *DeploymentBuilder) ipForwardInitContainer() corev1.Container {
	privileged := true
	return corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
		Image:           b.agentImage,
		ImagePullPolicy: b.agentImagePullPolicy,
		Name:            "sysctl",
		Command:         []string{"/bin/sh"},
		Args:            []string{"-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"},
	}
}
