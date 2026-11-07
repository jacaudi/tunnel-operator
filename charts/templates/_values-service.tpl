{{- define "tunnel-operator.values.service" -}}
service:
  metrics:
    controller: manager
    ports:
      metrics:
        port: 8080
        protocol: TCP
{{- end -}}
