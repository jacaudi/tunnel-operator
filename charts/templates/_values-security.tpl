{{- define "tunnel-operator.values.security" -}}
defaultPodOptions:
  # The manager needs its token to reach the API; common v5 defaults this to false.
  automountServiceAccountToken: true
  # Explicit Kubernetes defaults so bjw-s renders no nulls.
  hostIPC: false
  hostNetwork: false
  hostPID: false
  enableServiceLinks: true
  securityContext:
    fsGroup: 65534
    runAsNonRoot: true
  terminationGracePeriodSeconds: 10
{{- end -}}
