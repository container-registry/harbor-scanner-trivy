{{/* vim: set filetype=mustache: */}}

{{/*
Chart name, optionally overridden.
*/}}
{{- define "harbor-scanner-trivy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified resource name. Truncated at 63 characters for the DNS label
limit; the StatefulSet appends "-<ordinal>" to it for pod names, so the
practical budget is a little lower.
*/}}
{{- define "harbor-scanner-trivy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "harbor-scanner-trivy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels. These land in an immutable StatefulSet selector, so they must
never gain a value that changes between upgrades (the chart version, in
particular).
*/}}
{{- define "harbor-scanner-trivy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-scanner-trivy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "harbor-scanner-trivy.labels" -}}
helm.sh/chart: {{ include "harbor-scanner-trivy.chart" . }}
{{ include "harbor-scanner-trivy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: scanner-adapter
app.kubernetes.io/part-of: harbor
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Annotations for a rendered object: chart-wide commonAnnotations merged with the
object's own. Emits nothing when both are empty, so callers can guard with
`with` and avoid an empty `annotations:` key.
*/}}
{{- define "harbor-scanner-trivy.annotations" -}}
{{- $annotations := merge (deepCopy (.local | default dict)) (.root.Values.commonAnnotations | default dict) -}}
{{- with $annotations }}
{{- toYaml . }}
{{- end }}
{{- end -}}

{{/*
Image reference. global.imageRegistry wins over image.registry and preserves
the repository path; image.digest wins over image.tag.
*/}}
{{- define "harbor-scanner-trivy.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- $ref := .Values.image.repository -}}
{{- if $registry -}}
{{- $ref = printf "%s/%s" $registry .Values.image.repository -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $ref .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $ref (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
Merged pull secrets. Emits nothing when there are none, so the caller must
guard with `with` to avoid an empty line in the pod spec.
*/}}
{{- define "harbor-scanner-trivy.imagePullSecrets" -}}
{{- $names := list -}}
{{- if .Values.imageCredentials.create -}}
{{- $names = append $names (printf "%s-registry" (include "harbor-scanner-trivy.fullname" .)) -}}
{{- end -}}
{{- /* Both spellings are in the wild - a bare name and a LocalObjectReference -
      and they must be reduced to names before uniq, or "a" and {name: a}
      survive as two distinct entries. */ -}}
{{- range concat (.Values.global.imagePullSecrets | default list) (.Values.image.pullSecrets | default list) -}}
{{- if kindIs "string" . -}}
{{- $names = append $names . -}}
{{- else -}}
{{- $names = append $names (.name | default "") -}}
{{- end -}}
{{- end -}}
{{- range (compact $names | uniq) }}
- name: {{ . }}
{{- end }}
{{- end -}}

{{- define "harbor-scanner-trivy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "harbor-scanner-trivy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
TLS. Non-empty output means the API serves HTTPS.
*/}}
{{- define "harbor-scanner-trivy.tls.enabled" -}}
{{- if .Values.api.tls.enabled -}}enabled{{- end -}}
{{- end -}}

{{- define "harbor-scanner-trivy.tls.secretName" -}}
{{- .Values.api.tls.existingSecret | default (printf "%s-tls" (include "harbor-scanner-trivy.fullname" .)) -}}
{{- end -}}

{{/*
Mutual TLS. Non-empty output means client CA bundles are mounted, which makes
the adapter require and verify a client certificate.
*/}}
{{- define "harbor-scanner-trivy.tls.mtlsEnabled" -}}
{{- if and .Values.api.tls.enabled (or .Values.api.tls.clientCAs.existingSecret .Values.api.tls.clientCAs.existingConfigMap) -}}enabled{{- end -}}
{{- end -}}

{{/*
Comma-separated client CA paths for SCANNER_API_SERVER_CLIENT_CAS.
*/}}
{{- define "harbor-scanner-trivy.tls.clientCAPaths" -}}
{{- $paths := list -}}
{{- range .Values.api.tls.clientCAs.keys -}}
{{- $paths = append $paths (printf "/etc/scanner-trivy/client-cas/%s" .) -}}
{{- end -}}
{{- join "," $paths -}}
{{- end -}}

{{/*
Trivy ignore policy. Non-empty output is the ConfigMap name to mount.
*/}}
{{- define "harbor-scanner-trivy.ignorePolicyConfigMap" -}}
{{- if .Values.trivy.existingIgnorePolicyConfigMap -}}
{{- .Values.trivy.existingIgnorePolicyConfigMap -}}
{{- else if .Values.trivy.ignorePolicy -}}
{{- printf "%s-ignore-policy" (include "harbor-scanner-trivy.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
GitHub token source. Non-empty output is the Secret name holding it.
*/}}
{{- define "harbor-scanner-trivy.gitHubTokenSecretName" -}}
{{- if .Values.trivy.existingSecret -}}
{{- .Values.trivy.existingSecret -}}
{{- else if .Values.trivy.gitHubToken -}}
{{- include "harbor-scanner-trivy.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "harbor-scanner-trivy.gitHubTokenSecretKey" -}}
{{- if .Values.trivy.existingSecret -}}
{{- .Values.trivy.existingSecretKey -}}
{{- else -}}
gitHubToken
{{- end -}}
{{- end -}}

{{/*
Trivy debug mode. Unset follows the log level, matching the adapter's own
default (etc.GetConfig), so the chart must not pin it to false.
*/}}
{{- define "harbor-scanner-trivy.trivyDebugMode" -}}
{{- if kindIs "invalid" .Values.trivy.debugMode -}}
{{- if has (lower (toString .Values.logLevel)) (list "debug" "trace") -}}true{{- else -}}false{{- end -}}
{{- else -}}
{{- .Values.trivy.debugMode -}}
{{- end -}}
{{- end -}}

{{/*
Render one probe verbatim, injecting scheme: HTTPS when the API serves TLS and
the caller did not pick a scheme. Usage:
  {{- include "harbor-scanner-trivy.probe" (dict "root" $ "probe" .Values.probes.liveness) }}
*/}}
{{- define "harbor-scanner-trivy.probe" -}}
{{- $probe := deepCopy .probe -}}
{{- if and (include "harbor-scanner-trivy.tls.enabled" .root) (hasKey $probe "httpGet") -}}
{{- if not (hasKey $probe.httpGet "scheme") -}}
{{- $_ := set $probe.httpGet "scheme" "HTTPS" -}}
{{- end -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end -}}

{{- define "harbor-scanner-trivy.namespace" -}}
{{- .Release.Namespace -}}
{{- end -}}

{{/*
=============================================================================
Generic configuration passthrough
=============================================================================
*/}}

{{/*
Flatten a nested map into env-var assignments. Nested maps join with "_",
keys are uppercased, slices join with ",", and nil entries are skipped.
`isSecret` base64-encodes the values for a Secret's `data` block.

  config:
    scanner:
      trivy:
        timeout: 10m0s   ->   SCANNER_TRIVY_TIMEOUT: "10m0s"

No prefix is imposed: the adapter also reads HTTP_PROXY, HTTPS_PROXY and
NO_PROXY, which a forced SCANNER_ prefix would put out of reach.
*/}}
{{- define "harbor-scanner-trivy.toEnvVars" -}}
{{- $prefix := "" }}
{{- if .prefix }}{{- $prefix = printf "%s_" (.prefix | upper) }}{{- end }}
{{- range $key, $value := .values }}
{{- if kindIs "map" $value }}
{{- include "harbor-scanner-trivy.toEnvVars" (dict "values" $value "prefix" (printf "%s%s" $prefix ($key | upper)) "isSecret" $.isSecret) }}
{{- else if kindIs "slice" $value }}
{{ $prefix }}{{ $key | upper }}: {{ if $.isSecret }}{{ $value | join "," | b64enc | quote }}{{ else }}{{ $value | join "," | quote }}{{ end }}
{{- else if not (kindIs "invalid" $value) }}
{{ $prefix }}{{ $key | upper }}: {{ if $.isSecret }}{{ $value | toString | b64enc | quote }}{{ else }}{{ $value | toString | quote }}{{ end }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Env var names claimed by .Values.config / .Values.secret, as a YAML list.

This exists because envFrom is evaluated BEFORE env: a chart-set `env` entry
always beats an envFrom source of the same name. Without dropping the chart's
own entry, anything the user set through the passthrough would be silently
ignored.
*/}}
{{- define "harbor-scanner-trivy.claimedEnvNames" -}}
{{- $names := list -}}
{{- range $source := (list (.Values.config | default dict) (.Values.secret | default dict)) -}}
{{- range $name, $value := (include "harbor-scanner-trivy.toEnvVars" (dict "values" $source "prefix" "" "isSecret" false) | fromYaml) -}}
{{- $names = append $names $name -}}
{{- end -}}
{{- end -}}
{{- toYaml $names -}}
{{- end -}}

{{/*
The container's final `env` list: the chart's own entries minus anything
claimed by config/secret, then extraEnv appended.

Precedence, lowest to highest:
  chart defaults  <  config / secret (envFrom)  <  extraEnv
extraEnv wins over the passthrough for free, because it lands in `env`.
*/}}
{{- define "harbor-scanner-trivy.env" -}}
{{- $claimed := include "harbor-scanner-trivy.claimedEnvNames" . | fromYamlArray -}}
{{- $env := list -}}
{{- range (include "harbor-scanner-trivy.chartEnv" . | fromYamlArray) -}}
{{- if not (has .name $claimed) -}}
{{- $env = append $env . -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- $env = append $env . -}}
{{- end -}}
{{- toYaml $env -}}
{{- end -}}

{{/*
The chart's own environment, as a YAML list. Kept as data rather than
rendered inline so harbor-scanner-trivy.env can drop any entry whose name
the user claimed through .Values.config / .Values.secret.
*/}}
{{- define "harbor-scanner-trivy.chartEnv" -}}
{{- $tls := include "harbor-scanner-trivy.tls.enabled" . -}}
{{- $extraCA := include "harbor-scanner-trivy.extraCA.enabled" . -}}
{{- $mtls := include "harbor-scanner-trivy.tls.mtlsEnabled" . -}}
{{- $ignorePolicyConfigMap := include "harbor-scanner-trivy.ignorePolicyConfigMap" . -}}
{{- $gitHubTokenSecret := include "harbor-scanner-trivy.gitHubTokenSecretName" . -}}
- name: SCANNER_LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
- name: SCANNER_API_SERVER_ADDR
  value: ":{{ .Values.service.port }}"
- name: SCANNER_API_SERVER_READ_TIMEOUT
  value: {{ .Values.api.readTimeout | quote }}
- name: SCANNER_API_SERVER_WRITE_TIMEOUT
  value: {{ .Values.api.writeTimeout | quote }}
- name: SCANNER_API_SERVER_IDLE_TIMEOUT
  value: {{ .Values.api.idleTimeout | quote }}
- name: SCANNER_API_SERVER_METRICS_ENABLED
  value: {{ .Values.metrics.enabled | quote }}
{{- if $tls }}
- name: SCANNER_API_SERVER_TLS_CERTIFICATE
  value: /certs/tls.crt
- name: SCANNER_API_SERVER_TLS_KEY
  value: /certs/tls.key
{{- end }}
{{- if $mtls }}
- name: SCANNER_API_SERVER_CLIENT_CAS
  value: {{ include "harbor-scanner-trivy.tls.clientCAPaths" . | quote }}
{{- end }}
- name: SCANNER_TRIVY_CACHE_DIR
  value: {{ .Values.trivy.cacheDir | quote }}
- name: SCANNER_TRIVY_REPORTS_DIR
  value: {{ .Values.trivy.reportsDir | quote }}
- name: SCANNER_TRIVY_CACHE_BACKEND
  value: {{ .Values.trivy.cacheBackend | quote }}
- name: SCANNER_TRIVY_CACHE_TTL
  value: {{ .Values.trivy.cacheTTL | quote }}
- name: SCANNER_TRIVY_CACHE_MAX_SIZE
  value: {{ .Values.trivy.cacheMaxSize | quote }}
{{- if hasPrefix "redis" .Values.trivy.cacheBackend }}
- name: SCANNER_TRIVY_CACHE_REDIS_TLS
  value: {{ .Values.trivy.cacheRedisTLS | quote }}
{{- with .Values.trivy.cacheRedisCACert }}
- name: SCANNER_TRIVY_CACHE_REDIS_CA
  value: {{ . | quote }}
{{- end }}
{{- with .Values.trivy.cacheRedisCert }}
- name: SCANNER_TRIVY_CACHE_REDIS_CERT
  value: {{ . | quote }}
{{- end }}
{{- with .Values.trivy.cacheRedisKey }}
- name: SCANNER_TRIVY_CACHE_REDIS_KEY
  value: {{ . | quote }}
{{- end }}
{{- end }}
- name: SCANNER_TRIVY_DEBUG_MODE
  value: {{ include "harbor-scanner-trivy.trivyDebugMode" . | quote }}
- name: SCANNER_TRIVY_VULN_TYPE
  value: {{ .Values.trivy.vulnType | quote }}
- name: SCANNER_TRIVY_SECURITY_CHECKS
  value: {{ .Values.trivy.securityChecks | quote }}
- name: SCANNER_TRIVY_SEVERITY
  value: {{ .Values.trivy.severity | quote }}
- name: SCANNER_TRIVY_IGNORE_UNFIXED
  value: {{ .Values.trivy.ignoreUnfixed | quote }}
- name: SCANNER_TRIVY_TIMEOUT
  value: {{ .Values.trivy.timeout | quote }}
- name: SCANNER_TRIVY_SKIP_UPDATE
  value: {{ .Values.trivy.skipUpdate | quote }}
- name: SCANNER_TRIVY_SKIP_JAVA_DB_UPDATE
  value: {{ .Values.trivy.skipJavaDBUpdate | quote }}
- name: SCANNER_TRIVY_DB_REPOSITORY
  value: {{ .Values.trivy.dbRepository | quote }}
- name: SCANNER_TRIVY_JAVA_DB_REPOSITORY
  value: {{ .Values.trivy.javaDBRepository | quote }}
- name: SCANNER_TRIVY_OFFLINE_SCAN
  value: {{ .Values.trivy.offlineScan | quote }}
- name: SCANNER_TRIVY_INSECURE
  value: {{ .Values.trivy.insecure | quote }}
- name: SCANNER_TRIVY_USE_SBOM_ACCESSORY
  value: {{ .Values.trivy.useSBOMAccessory | quote }}
{{- with .Values.trivy.vexSource }}
- name: SCANNER_TRIVY_VEX_SOURCE
  value: {{ . | quote }}
- name: SCANNER_TRIVY_SKIP_VEX_REPO_UPDATE
  value: {{ $.Values.trivy.skipVEXRepoUpdate | quote }}
{{- end }}
{{- if $ignorePolicyConfigMap }}
- name: SCANNER_TRIVY_IGNORE_POLICY
  value: {{ printf "/home/scanner/opa/%s" .Values.trivy.ignorePolicyKey | quote }}
{{- end }}
{{- if $gitHubTokenSecret }}
- name: SCANNER_TRIVY_GITHUB_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $gitHubTokenSecret }}
      key: {{ include "harbor-scanner-trivy.gitHubTokenSecretKey" . }}
{{- end }}
- name: SCANNER_STORE_REDIS_NAMESPACE
  value: {{ .Values.store.redisNamespace | quote }}
{{- with .Values.store.redisScanJobTTL }}
- name: SCANNER_STORE_REDIS_SCAN_JOB_TTL
  value: {{ . | quote }}
{{- end }}
- name: SCANNER_JOB_QUEUE_REDIS_NAMESPACE
  value: {{ .Values.jobQueue.redisNamespace | quote }}
- name: SCANNER_JOB_QUEUE_WORKER_CONCURRENCY
  value: {{ .Values.jobQueue.workerConcurrency | quote }}
{{- if .Values.redis.existingSecret }}
{{- /* The URL carries the Redis password, so it is read from the
       Secret rather than inlined into the pod spec. */}}
- name: SCANNER_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.existingSecret }}
      key: {{ .Values.redis.existingSecretKey }}
{{- else }}
- name: SCANNER_REDIS_URL
  value: {{ .Values.redis.url | quote }}
{{- end }}
- name: SCANNER_REDIS_POOL_MAX_ACTIVE
  value: {{ .Values.redis.pool.maxActive | quote }}
- name: SCANNER_REDIS_POOL_MAX_IDLE
  value: {{ .Values.redis.pool.maxIdle | quote }}
- name: SCANNER_REDIS_POOL_IDLE_TIMEOUT
  value: {{ .Values.redis.pool.idleTimeout | quote }}
- name: SCANNER_REDIS_POOL_CONNECTION_TIMEOUT
  value: {{ .Values.redis.pool.connectionTimeout | quote }}
- name: SCANNER_REDIS_POOL_READ_TIMEOUT
  value: {{ .Values.redis.pool.readTimeout | quote }}
- name: SCANNER_REDIS_POOL_WRITE_TIMEOUT
  value: {{ .Values.redis.pool.writeTimeout | quote }}
{{- with .Values.proxy.httpProxy }}
- name: HTTP_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.httpsProxy }}
- name: HTTPS_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.noProxy }}
- name: NO_PROXY
  value: {{ . | quote }}
{{- end }}
{{- if $extraCA }}
{{- /* Go's crypto/x509 REPLACES its default directory list when SSL_CERT_DIR
      is set, so the system bundle has to be named explicitly or every public
      TLS call breaks - starting with the Trivy DB download from ghcr.io.
      Order is irrelevant: a cert in any listed directory is trusted. */}}
- name: SSL_CERT_DIR
  value: "/etc/ssl/certs:/etc/scanner-trivy/extra-ca"
{{- end }}
{{- end -}}

{{/*
=============================================================================
Extra CA trust
=============================================================================
*/}}

{{/*
Non-empty when a private CA bundle is mounted.
*/}}
{{- define "harbor-scanner-trivy.extraCA.enabled" -}}
{{- if or .Values.extraCA.existingSecret .Values.extraCA.existingConfigMap -}}enabled{{- end -}}
{{- end -}}

{{- define "harbor-scanner-trivy.extraCA.volume" -}}
{{- if include "harbor-scanner-trivy.extraCA.enabled" . }}
- name: extra-ca
  {{- if .Values.extraCA.existingSecret }}
  secret:
    secretName: {{ .Values.extraCA.existingSecret }}
  {{- else }}
  configMap:
    name: {{ .Values.extraCA.existingConfigMap }}
  {{- end }}
  {{- with .Values.extraCA.keys }}
    items:
      {{- range . }}
      - key: {{ . }}
        path: {{ . }}
      {{- end }}
  {{- end }}
{{- end }}
{{- end -}}

{{- define "harbor-scanner-trivy.extraCA.volumeMount" -}}
{{- if include "harbor-scanner-trivy.extraCA.enabled" . }}
- name: extra-ca
  mountPath: /etc/scanner-trivy/extra-ca
  readOnly: true
{{- end }}
{{- end -}}

