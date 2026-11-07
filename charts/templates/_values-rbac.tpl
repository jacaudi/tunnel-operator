{{/*
AUTO-GENERATED from config/rbac/ by hack/generate-helm-rbac.sh — DO NOT EDIT
*/}}
{{- define "tunnel-operator.values.rbac" -}}
rbac:
  roles:
    manager:
      type: ClusterRole
      forceRename: tunnel-operator-manager
      rules:
        - apiGroups:
            - ""
          resources:
            - pods
            - secrets
            - services
          verbs:
            - create
            - delete
            - get
            - list
            - patch
            - update
            - watch
        - apiGroups:
            - admissionregistration.k8s.io
          resourceNames:
            - tunnel-operator-inject
          resources:
            - mutatingadmissionpolicies
            - mutatingadmissionpolicybindings
          verbs:
            - create
            - delete
            - patch
        - apiGroups:
            - apps
          resources:
            - deployments
            - pods
          verbs:
            - create
            - delete
            - get
            - list
            - patch
            - update
            - watch
        - apiGroups:
            - authentication.k8s.io
          resources:
            - tokenreviews
          verbs:
            - create
        - apiGroups:
            - authorization.k8s.io
          resources:
            - subjectaccessreviews
          verbs:
            - create
        - apiGroups:
            - rbac.authorization.k8s.io
          resourceNames:
            - tunnel-operator-client
          resources:
            - clusterroles
          verbs:
            - bind
        - apiGroups:
            - rbac.authorization.k8s.io
          resourceNames:
            - tunnel-operator-client
          resources:
            - rolebindings
          verbs:
            - create
            - delete
            - get
            - list
            - patch
            - watch
        - apiGroups:
            - vpn.tunnel-operator.io
          resources:
            - wireguardpeers
          verbs:
            - get
            - list
            - watch
        - apiGroups:
            - vpn.tunnel-operator.io
          resources:
            - wireguardpeers/status
            - wireguards/status
          verbs:
            - get
            - patch
            - update
        - apiGroups:
            - vpn.tunnel-operator.io
          resources:
            - wireguards
          verbs:
            - create
            - delete
            - get
            - list
            - patch
            - update
            - watch
        - apiGroups:
            - vpn.tunnel-operator.io
          resources:
            - wireguards/finalizers
          verbs:
            - update
    leader-election:
      type: Role
      rules:
        - apiGroups:
            - ""
          resources:
            - configmaps
          verbs:
            - get
            - list
            - watch
            - create
            - update
            - patch
            - delete
        - apiGroups:
            - coordination.k8s.io
          resources:
            - leases
          verbs:
            - get
            - list
            - watch
            - create
            - update
            - patch
            - delete
        - apiGroups:
            - ""
          resources:
            - events
          verbs:
            - create
            - patch
    client:
      type: ClusterRole
      forceRename: tunnel-operator-client
      rules:
        - apiGroups:
            - vpn.tunnel-operator.io
          resources:
            - wireguardpeers
          verbs:
            - create
            - delete
            - get
            - list
            - watch
    metrics-reader:
      type: ClusterRole
      forceRename: tunnel-operator-metrics-reader
      rules:
        - nonResourceURLs:
            - "/metrics"
          verbs:
            - get
  bindings:
    manager:
      type: ClusterRoleBinding
      forceRename: tunnel-operator-manager
      roleRef:
        identifier: manager
      subjects:
        - identifier: manager
    leader-election:
      type: RoleBinding
      roleRef:
        identifier: leader-election
      subjects:
        - identifier: manager
    metrics-reader:
      type: ClusterRoleBinding
      forceRename: tunnel-operator-metrics-reader
      roleRef:
        identifier: metrics-reader
      subjects:
        - identifier: metrics-reader
{{- end -}}
