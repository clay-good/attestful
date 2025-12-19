{{/*
Expand the name of the chart.
*/}}
{{- define "attestful.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "attestful.fullname" -}}
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
{{- define "attestful.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "attestful.labels" -}}
helm.sh/chart: {{ include "attestful.chart" . }}
{{ include "attestful.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "attestful.selectorLabels" -}}
app.kubernetes.io/name: {{ include "attestful.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "attestful.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "attestful.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "attestful.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- $host := printf "%s-postgresql" (include "attestful.fullname" .) }}
{{- $port := "5432" }}
{{- $user := .Values.postgresql.auth.username }}
{{- $database := .Values.postgresql.auth.database }}
{{- printf "postgresql://%s:$(DATABASE_PASSWORD)@%s:%s/%s" $user $host $port $database }}
{{- else }}
{{- .Values.externalDatabase.url }}
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "attestful.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- $host := printf "%s-redis-master" (include "attestful.fullname" .) }}
{{- printf "redis://:%s@%s:6379/0" "$(REDIS_PASSWORD)" $host }}
{{- else if .Values.externalRedis.url }}
{{- .Values.externalRedis.url }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Secret name for JWT
*/}}
{{- define "attestful.jwtSecretName" -}}
{{- if .Values.secrets.existingJwtSecret }}
{{- .Values.secrets.existingJwtSecret }}
{{- else }}
{{- printf "%s-jwt" (include "attestful.fullname" .) }}
{{- end }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "attestful.configMapName" -}}
{{- printf "%s-config" (include "attestful.fullname" .) }}
{{- end }}

{{/*
Image name
*/}}
{{- define "attestful.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
