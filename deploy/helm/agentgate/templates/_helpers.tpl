{{/*
Expand the name of the chart.
*/}}
{{- define "agentgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "agentgate.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "agentgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "agentgate.labels" -}}
helm.sh/chart: {{ include "agentgate.chart" . }}
{{ include "agentgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "agentgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "agentgate.serviceAccountName" -}}
{{- if .Values.server.serviceAccount.create }}
{{- default (include "agentgate.fullname" .) .Values.server.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.server.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL connection string
*/}}
{{- define "agentgate.databaseUrl" -}}
{{- $dbAuthMode := (default "auto" .Values.server.env.DATABASE_AUTH_MODE | lower) -}}
{{- if .Values.postgresql.enabled }}
{{- if eq $dbAuthMode "entra_token" }}
postgresql+asyncpg://{{ .Values.postgresql.auth.username }}@{{ include "agentgate.fullname" . }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else }}
postgresql+asyncpg://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ include "agentgate.fullname" . }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- end }}
{{- else }}
{{- .Values.externalDatabase.url }}
{{- end }}
{{- end }}

{{/*
Redis connection string
*/}}
{{- define "agentgate.redisUrl" -}}
{{- if .Values.redis.enabled }}
redis://:{{ .Values.redis.auth.password }}@{{ include "agentgate.fullname" . }}-redis-master:6379/0
{{- else }}
{{- .Values.externalRedis.url }}
{{- end }}
{{- end }}
