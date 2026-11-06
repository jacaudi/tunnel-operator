package resources

const (
	// LabelEnabled opts a pod in to sidecar injection when its value is "true".
	LabelEnabled = "tunnel-operator.io/enabled"

	// LabelComponent marks a pod the operator itself runs. Both injection policies skip any pod that
	// carries it, whatever its value: the gateway's traffic would otherwise loop through itself.
	LabelComponent = "tunnel-operator.io/component"

	// ComponentGateway is LabelComponent's value on a gateway pod.
	ComponentGateway = "gateway"

	// SidecarContainer names the injected client container, always the first init container. The static
	// backstop recognises an injected pod by it.
	SidecarContainer = "wg-client"

	// ComponentOperator is LabelComponent's value on the manager's pod.
	ComponentOperator = "operator"
)

const (
	// AnnotationDefault marks the Wireguard that injected sidecars attach to, when its value is "true".
	// Only a Wireguard in the operator's own namespace counts.
	AnnotationDefault = "tunnel-operator.io/default"

	// LabelManagedBy and ManagedByValue label every object the operator writes at runtime, so a
	// selector can find (and delete) them all: the uninstall cleanup in docs/injection.md uses it.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByValue is LabelManagedBy's value.
	ManagedByValue = "tunnel-operator"

	// VolumeKey is the injected sidecar's in-memory key volume, VolumeToken its own ServiceAccount token.
	VolumeKey = "wg-key"
	// VolumeToken is the projected token volume mounted only into the sidecar.
	VolumeToken = "wg-token"
)

// ClientRoleName names both the client ClusterRole as rendered in release.yaml (the config/ name
// operator-client plus the release's tunnel- prefix) and the RoleBinding the operator creates to it in
// each namespace with injected pods. It is literal because the operator writes the RoleBinding at runtime.
const ClientRoleName = "tunnel-operator-client"
