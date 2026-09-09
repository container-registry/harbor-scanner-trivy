{{/* Resolve the upstream primary Service using the subchart's own naming rules. */}}
{{- define "harbor-scanner-trivy.cacheBackend" -}}
{{- if and .Values.valkey.enabled (eq .Values.trivy.cacheBackend "fs") -}}
{{- $scheme := ternary "rediss" "redis" .Values.valkey.tls.enabled -}}
{{- printf "%s://%s:%v/0" $scheme (include "valkey.fullname" .Subcharts.valkey) .Subcharts.valkey.Values.service.port -}}
{{- else -}}
{{- .Values.trivy.cacheBackend -}}
{{- end -}}
{{- end -}}
