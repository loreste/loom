{{- define "loom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "loom.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "loom.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "loom.labels" -}}
app.kubernetes.io/name: {{ include "loom.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "loom.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "loom.fullname" .) .Values.serviceAccount.name }}{{ else }}{{ default "default" .Values.serviceAccount.name }}{{ end }}
{{- end -}}

{{- define "loom.image" -}}
{{- if .Values.image.digest }}{{ .Values.image.repository }}@{{ .Values.image.digest }}{{ else }}{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}{{ end }}
{{- end -}}

{{- define "loom.secretName" -}}
{{- required "secrets.existingSecret must reference an externally managed Secret" .Values.secrets.existingSecret -}}
{{- end -}}
