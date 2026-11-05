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
)

// WireguardPeerSpec defines the desired state of WireguardPeer
type WireguardPeerSpec struct {
	// The key used by the peer to authenticate with the wg server.
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$`
	PublicKey string `json:"publicKey,omitempty"`
	// The name of the Wireguard instance in k8s that the peer belongs to. The wg instance should be in the same namespace as the peer.
	//+kubebuilder:validation:Required
	//+kubebuilder:validation:MinLength=1
	WireguardRef string `json:"wireguardRef"`
}

// WireguardPeerStatus defines the observed state of WireguardPeer
type WireguardPeerStatus struct {
	// A string field that represents the current status of the Wireguard peer. This could include values like ready, pending, or error.
	Status string `json:"status,omitempty"`
	// A string field that provides additional information about the status of the Wireguard peer. This could include error messages or other information that helps to diagnose issues with the peer.
	Message string `json:"message,omitempty"`
	// Address is the peer's IPv4 tunnel address, without a prefix length, allocated by the operator
	// from the server's peerCIDR. The server routes <address>/32 to this peer.
	Address string `json:"address,omitempty"`
	// Conditions represent the latest available observations of the WireguardPeer's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireguardPeer is the Schema for the wireguardpeers API
type WireguardPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// The desired state of the peer.
	Spec WireguardPeerSpec `json:"spec,omitempty"`
	// A field that defines the observed state of the Wireguard peer. This includes fields like the current configuration and status of the peer.
	Status WireguardPeerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WireguardPeerList contains a list of WireguardPeer
type WireguardPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireguardPeer `json:"items"`
}
