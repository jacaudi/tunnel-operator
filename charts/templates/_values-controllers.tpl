{{- define "tunnel-operator.values.controllers" -}}
{{- $resources := .Values.manager.resources | default (dict "requests" (dict "cpu" "10m" "memory" "64Mi") "limits" (dict "cpu" "500m" "memory" "128Mi")) -}}
controllers:
  manager:
    type: deployment
    replicas: 1
    strategy: RollingUpdate
    serviceAccount:
      identifier: manager
    pod:
      labels:
        tunnel-operator.io/component: operator
      annotations:
        kubectl.kubernetes.io/default-container: manager
    containers:
      manager:
        image:
          repository: {{ .Values.manager.image.repository }}
          tag: {{ include "tunnel-operator.managerTag" . | quote }}
          pullPolicy: {{ .Values.manager.image.pullPolicy }}
        command:
          - /manager
        args:
          - --health-probe-bind-address=:8081
          - --metrics-bind-address=:8080
          - --leader-elect
          - {{ printf "--agent-image=%s" (include "tunnel-operator.agentImage" .) | quote }}
        env:
          POD_NAMESPACE:
            fieldRef:
              fieldPath: metadata.namespace
        resources:
          {{- toYaml $resources | nindent 10 }}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsUser: 65534
          runAsGroup: 65534
          capabilities:
            drop:
              - ALL
        probes:
          liveness:
            enabled: true
            custom: true
            spec:
              httpGet:
                path: /healthz
                port: 8081
              initialDelaySeconds: 15
              periodSeconds: 20
          readiness:
            enabled: true
            custom: true
            spec:
              httpGet:
                path: /readyz
                port: 8081
              initialDelaySeconds: 5
              periodSeconds: 10
{{- end -}}
