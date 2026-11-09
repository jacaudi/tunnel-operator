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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"
)

const (
	Pending = "pending"
	Error   = "error"
	Ready   = "ready"
)

// WireguardSpec defines the desired state of Wireguard
type WireguardSpec struct {
	// PeerCIDR is the IPv4 CIDR range from which Wireguard peer addresses will be allocated.
	// If omitted, the operator will default to 10.8.0.0/24.
	PeerCIDR string `json:"peerCIDR,omitempty"`
	// LocalCIDRs lists the cluster's pod, Service and node CIDRs, plus 169.254.20.10/32 when NodeLocal
	// DNSCache is in use. Clients route these over the CNI, never through the tunnel, and the server
	// hands them to gluetun as FIREWALL_OUTBOUND_SUBNETS. Each entry must be a canonical IPv4 CIDR;
	// the Service's ClusterIP must fall inside one, and none may overlap peerCIDR.
	// +kubebuilder:validation:MinItems=1
	LocalCIDRs []string `json:"localCIDRs"`
	// Gluetun configures the gluetun container that carries the server's egress to the VPN provider.
	Gluetun      GluetunSpec       `json:"gluetun"`
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// A list of Kubernetes taint tolerations applied to the Wireguard pod.
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	Agent       WireguardPodSpec    `json:"agent,omitempty"`
	// AllowedNamespaces says which namespaces may attach peers to this Wireguard. Omitted means all.
	// +optional
	AllowedNamespaces *AllowedNamespaces `json:"allowedNamespaces,omitempty"`
}

// FromNamespaces says which namespaces an AllowedNamespaces admits.
type FromNamespaces string

// Values of AllowedNamespaces.From.
const (
	// FromAll admits peers from every namespace.
	FromAll FromNamespaces = "All"
	// FromSame admits only peers in the Wireguard's own namespace.
	FromSame FromNamespaces = "Same"
)

// AllowedNamespaces selects the namespaces whose peers a Wireguard admits.
type AllowedNamespaces struct {
	// From is All (peers from every namespace) or Same (only the Wireguard's own namespace).
	// +kubebuilder:validation:Enum=All;Same
	// +kubebuilder:default=All
	From FromNamespaces `json:"from,omitempty"`
}

// WireguardPodSpec defines spec for respective containers created for Wireguard
type WireguardPodSpec struct {
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// GluetunSpec is passed through to the gluetun container. The operator renders the variables its
// routing depends on (VPN_TYPE, VPN_INTERFACE, the firewall settings, HEALTH_SERVER_ADDRESS,
// WIREGUARD_MTU, HTTP_CONTROL_SERVER_ADDRESS, HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH,
// HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE and VPN_PORT_FORWARDING_LISTENING_PORT) and reports Degraded if
// env or a referenced Secret sets one of them. Other HTTP_CONTROL_SERVER_* variables, such as
// HTTP_CONTROL_SERVER_LOG, are not reserved.
type GluetunSpec struct {
	// Env is passed through to the gluetun container, after the variables the operator renders.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`
	// EnvFrom is passed through to the gluetun container. Reference provider credentials from a
	// Secret here rather than writing them inline in env.
	// +optional
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`
	// Resources are the gluetun container's requests and limits.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// PortForwarding configures the forwarded port the operator routes to the holder pod.
	// +optional
	PortForwarding *PortForwardingSpec `json:"portForwarding,omitempty"`
}

// PortForwardingSpec configures the forwarded port.
type PortForwardingSpec struct {
	// StaticPort is a provider-assigned fixed forwarded port (for example from AirVPN's dashboard).
	// When set, the agent forwards it instead of asking gluetun.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	StaticPort int32 `json:"staticPort,omitempty"`
}

// WireguardStatus defines the observed state of Wireguard
type WireguardStatus struct {
	// A string field that represents the current status of Wireguard. This could include values like ready, pending, or error.
	Status string `json:"status,omitempty"`
	// A string field that provides additional information about the status of Wireguard. This could include error messages or other information that helps to diagnose issues with the wg instance.
	Message string `json:"message,omitempty"`
	// Endpoint is the address a client dials: the server Service's ClusterIP and the WireGuard port,
	// as host:port.
	Endpoint string `json:"endpoint,omitempty"`
	// PublicKey is the server's WireGuard public key.
	PublicKey string `json:"publicKey,omitempty"`
	// Conditions represent the latest available observations of the Wireguard's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
	// EgressAPI is the egress API URL attached pods call: http://<server tunnel address>:8081.
	EgressAPI string `json:"egressAPI,omitempty"`
	// Egress is what gluetun reports for this server, refreshed about every 30 s.
	// +optional
	Egress *EgressStatus `json:"egress,omitempty"`
}

// EgressStatus is the egress state the gateway agent reports for a server.
type EgressStatus struct {
	// ExitIP is the public IP the server egresses from.
	ExitIP string `json:"exitIP,omitempty"`
	// ForwardedPort is the provider-forwarded port in use: spec.gluetun.portForwarding.staticPort when
	// set, else the port gluetun reports.
	ForwardedPort int32 `json:"forwardedPort,omitempty"`
	// ForwardedPortPeer is the peer holding the forwarded port, as <namespace>/<peer name>.
	ForwardedPortPeer string `json:"forwardedPortPeer,omitempty"`
	// LastCycle is the most recent VPN cycle the agent finished.
	// +optional
	LastCycle *CycleResult `json:"lastCycle,omitempty"`
	// LastHandledAnnotation is the last tunnel-operator.io/cycle-requested-at value the agent acted on.
	LastHandledAnnotation string `json:"lastHandledAnnotation,omitempty"`
}

// CycleResult is the outcome of one VPN cycle.
type CycleResult struct {
	// Reason is Succeeded, IPUnchanged, EmptyIP, Timeout or GluetunError.
	Reason string `json:"reason"`
	// OldExitIP is the exit IP before the cycle.
	OldExitIP string `json:"oldExitIP,omitempty"`
	// NewExitIP is the exit IP after the cycle.
	NewExitIP string `json:"newExitIP,omitempty"`
	// Trigger is what started the cycle: api:<peer address> or annotation:<value>.
	Trigger string `json:"trigger"`
	// FinishedAt is when the cycle finished, truncated to seconds.
	FinishedAt metav1.Time `json:"finishedAt"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Exit IP",type=string,JSONPath=`.status.egress.exitIP`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.status.egress.forwardedPort`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Wireguard is the Schema for the wireguards API
type Wireguard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireguardSpec   `json:"spec,omitempty"`
	Status WireguardStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WireguardList contains a list of Wireguard
type WireguardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Wireguard `json:"items"`
}
