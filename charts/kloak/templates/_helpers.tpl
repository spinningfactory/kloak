{{/*
Expand the name of the chart.
*/}}
{{- define "kloak.name" -}}
kloak
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 characters because some Kubernetes name fields are limited to this.
*/}}
{{- define "kloak.fullname" -}}
{{- $name := include "kloak.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kloak.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "kloak.labels" -}}
app.kubernetes.io/name: {{ include "kloak.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "kloak.chart" . }}
{{- end }}

{{/*
Selector labels (used in matchLabels).
*/}}
{{- define "kloak.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kloak.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Certificate secret name.
*/}}
{{- define "kloak.certSecretName" -}}
{{- if eq .Values.certificates.mode "provided" -}}
{{ .Values.certificates.provided.secretName }}
{{- else -}}
kloak-webhook-certs
{{- end -}}
{{- end -}}

