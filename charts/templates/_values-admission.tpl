{{/*
AUTO-GENERATED from config/admission/ by hack/sync-helm-crds.sh — DO NOT EDIT
*/}}
{{- define "tunnel-operator.values.admission" -}}
rawResources:
  require-injection-policy:
    forceRename: {{ include "tunnel-operator.requireInjectionName" . }}
    manifest:
      apiVersion: admissionregistration.k8s.io/v1
      kind: ValidatingAdmissionPolicy
      spec:
        failurePolicy: Fail
        matchConstraints:
          resourceRules:
            - apiGroups: [""]
              apiVersions: ["v1"]
              operations: ["CREATE"]
              resources: ["pods"]
        validations:
          - expression: "!has(object.spec.hostNetwork) || !object.spec.hostNetwork"
            message: "hostNetwork pods cannot be tunnelled"
          - expression: >-
              has(object.spec.initContainers) && size(object.spec.initContainers) > 0 && object.spec.initContainers[0].name == 'wg-client' && has(object.spec.initContainers[0].restartPolicy) && object.spec.initContainers[0].restartPolicy == 'Always'
            message: >-
              the pod is labelled tunnel-operator.io/enabled=true but was not injected with the WireGuard sidecar. Check that exactly one Wireguard in the operator's namespace is annotated tunnel-operator.io/default=true, that the operator is running, and that the cluster serves MutatingAdmissionPolicy (Kubernetes 1.34 and 1.35 need the beta enabled). The operator's log names the cause.
  require-injection-binding:
    forceRename: {{ include "tunnel-operator.requireInjectionName" . }}
    manifest:
      apiVersion: admissionregistration.k8s.io/v1
      kind: ValidatingAdmissionPolicyBinding
      spec:
        policyName: {{ include "tunnel-operator.requireInjectionName" . }}
        validationActions: [Deny]
        matchResources:
          objectSelector:
            matchLabels:
              tunnel-operator.io/enabled: "true"
            matchExpressions:
              - key: tunnel-operator.io/component
                operator: DoesNotExist
          namespaceSelector:
            matchExpressions:
              - key: kubernetes.io/metadata.name
                operator: NotIn
                values: [kube-system]
{{- end -}}
