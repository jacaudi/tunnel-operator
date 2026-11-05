package resources

const (
	// LabelEnabled opts a pod in to sidecar injection when its value is "true".
	LabelEnabled = "wireguard-operator.io/enabled"

	// LabelComponent marks a pod the operator itself runs. Both injection policies skip any pod that
	// carries it, whatever its value: the gateway's traffic would otherwise loop through itself.
	LabelComponent = "wireguard-operator.io/component"

	// ComponentGateway is LabelComponent's value on a gateway pod.
	ComponentGateway = "gateway"

	// ComponentOperator is LabelComponent's value on the manager's pod.
	ComponentOperator = "operator"
)
