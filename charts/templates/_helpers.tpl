{{/* Image tag helpers: the values tag, else "v" + appVersion with any leading "v" trimmed. */}}
{{- define "tunnel-operator.managerTag" -}}
{{- .Values.manager.image.tag | default (printf "v%s" (trimPrefix "v" .Chart.AppVersion)) -}}
{{- end -}}

{{- define "tunnel-operator.agentTag" -}}
{{- .Values.agent.image.tag | default (printf "v%s" (trimPrefix "v" .Chart.AppVersion)) -}}
{{- end -}}

{{/* The agent image the manager injects; passed to it as --agent-image. */}}
{{- define "tunnel-operator.agentImage" -}}
{{- printf "%s:%s" .Values.agent.image.repository (include "tunnel-operator.agentTag" .) -}}
{{- end -}}

{{/* One name for the admission policy and its binding; they are linked only by this string. */}}
{{- define "tunnel-operator.requireInjectionName" -}}
tunnel-operator-require-injection
{{- end -}}
