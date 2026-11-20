{{/*
Expand the name of the chart.
*/}}
{{- define "gateway-protector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "gateway-protector.fullname" -}}
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
{{- define "gateway-protector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace for all namespaced resources of the chart.
It is namespaceOverride, or the release namespace when namespaceOverride is empty.
*/}}
{{- define "gateway-protector.namespace" -}}
{{- $override := .Values.namespaceOverride | default "" -}}
{{- $override | default .Release.Namespace -}}
{{- end -}}

{{/*
Registry prefix for the chart images, with a trailing "/".
global.imageRegistry wins over the image.registry of the workload block.
It takes the context dict of the workload helpers.
*/}}
{{- define "gateway-protector.registry" -}}
{{- $global := .root.Values.global | default dict -}}
{{- with $global.imageRegistry | default (include "gateway-protector._image" . | fromYaml).registry -}}
{{- printf "%s/" . -}}
{{- end -}}
{{- end -}}

{{/*
gateway-protector._image renders the image map of the workload block as YAML,
or an empty map when the block has no image.
It takes the context dict of the workload helpers.
*/}}
{{- define "gateway-protector._image" -}}
{{- $block := index .root.Values .workload | default dict -}}
{{- toYaml ($block.image | default dict) -}}
{{- end -}}

{{/*
gateway-protector.image renders the full image reference of the workload block.
It takes the context dict of the workload helpers.
*/}}
{{- define "gateway-protector.image" -}}
{{- $image := include "gateway-protector._image" . | fromYaml -}}
{{- printf "%s%s:%s" (include "gateway-protector.registry" .) $image.repository $image.tag -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "gateway-protector.labels" -}}
helm.sh/chart: {{ include "gateway-protector.chart" . }}
{{ include "gateway-protector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/part-of: gateway-protector
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "gateway-protector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gateway-protector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Convert labels rendered as YAML (e.g. "k: v\nk2: v2") into a comma-separated selector string "k=v,k2=v2".
Usage:
  {{ include "gateway-protector.labelSelectorToString" (include "gateway-protector.selectorLabels" .) }}
*/}}
{{- define "gateway-protector.labelSelectorToString" -}}
{{- $yaml := . | default "" -}}
{{- $m := (fromYaml $yaml) | default dict -}}
{{- $keys := keys $m | sortAlpha -}}
{{- $out := list -}}
{{- range $k := $keys -}}
  {{- $out = append $out (printf "%s=%v" $k (get $m $k)) -}}
{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{/*
Values of the workloads

The workload templates read their values through the public helpers below.
Each public helper takes a context dict:
  root:      the root context ($)
  workload:  the name of the workload block in .Values: "controller" or "processor"
  component: the value of the app.kubernetes.io/component label, for example "controller"

A template builds the context dict once:
  {{- $ctx := dict "root" $ "workload" "controller" "component" "controller" }}

Each public helper reads one key with one private helper. The private helper sets the rule:
  gateway-protector._scalar: the workload value, else the common value, else the global value.
  gateway-protector._list:   the same rule as gateway-protector._scalar, for a list.
  gateway-protector._map:    the global, common, and workload maps merged. The workload wins on a duplicate key.
  gateway-protector._concat: the global, common, and workload lists, in this order.
An empty value ("", [] or {}) counts as unset.
The image registry and the pull policy of a workload are in its image map:
  gateway-protector.registry (above): global.imageRegistry, else the workload image.registry.
  gateway-protector.imagePullPolicy: the workload image.pullPolicy, else common.imagePullPolicy,
                                     else global.imagePullPolicy.

The private helpers take dict "ctx" <context dict> "key" <key>.
A key with a dot, for example "serviceAccount.annotations", reads a nested map.
Templates do not call the private helpers.
*/}}

{{/*
gateway-protector._levels renders a YAML list with three items:
the value of the key in global, in common, and in the workload block.
The other private helpers decode this list, so they work on copies of .Values.
*/}}
{{- define "gateway-protector._levels" -}}
{{- $values := .ctx.root.Values -}}
{{- $blocks := list ($values.global | default dict) ($values.common | default dict) (index $values .ctx.workload | default dict) -}}
{{- $out := list -}}
{{- range $block := $blocks -}}
{{- $value := $block -}}
{{- range $part := splitList "." $.key -}}
{{- $value = index ($value | default dict) $part -}}
{{- end -}}
{{- $out = append $out $value -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{- define "gateway-protector._scalar" -}}
{{- $l := include "gateway-protector._levels" . | fromYamlArray -}}
{{- index $l 2 | default (index $l 1) | default (index $l 0) | default "" -}}
{{- end -}}

{{- define "gateway-protector._list" -}}
{{- $l := include "gateway-protector._levels" . | fromYamlArray -}}
{{- toYaml (index $l 2 | default (index $l 1) | default (index $l 0) | default list) -}}
{{- end -}}

{{- define "gateway-protector._map" -}}
{{- $l := include "gateway-protector._levels" . | fromYamlArray -}}
{{- toYaml (mergeOverwrite (dict) (index $l 0 | default dict) (index $l 1 | default dict) (index $l 2 | default dict)) -}}
{{- end -}}

{{- define "gateway-protector._concat" -}}
{{- $l := include "gateway-protector._levels" . | fromYamlArray -}}
{{- toYaml (concat (index $l 0 | default list) (index $l 1 | default list) (index $l 2 | default list)) -}}
{{- end -}}

{{/*
gateway-protector._field renders "<name>:" and the value as YAML.
It renders nothing when the value is empty.
It takes dict "name" <field name> "value" <value>.
*/}}
{{- define "gateway-protector._field" -}}
{{- with .value -}}
{{ $.name }}:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}

{{/*
gateway-protector._labels renders "labels:" with the merged map of the key
and the fixed chart labels. The fixed chart labels win on a duplicate key.
It takes dict "ctx" <context dict> "key" <key>.
*/}}
{{- define "gateway-protector._labels" -}}
{{- $labels := include "gateway-protector._map" . | fromYaml -}}
{{- $fixed := include "gateway-protector.labels" .ctx.root | fromYaml -}}
{{- $_ := set $fixed "app.kubernetes.io/component" .ctx.component -}}
labels:
  {{- toYaml (mergeOverwrite $labels $fixed) | nindent 2 }}
{{- end -}}

{{/* Public helpers that render a bare value. */}}

{{- define "gateway-protector.imagePullPolicy" -}}
{{- $l := include "gateway-protector._levels" (dict "ctx" . "key" "imagePullPolicy") | fromYamlArray -}}
{{- (include "gateway-protector._image" . | fromYaml).pullPolicy | default (index $l 1) | default (index $l 0) | default "" -}}
{{- end -}}

{{- define "gateway-protector.logLevel" -}}
{{- include "gateway-protector._scalar" (dict "ctx" . "key" "logLevel") -}}
{{- end -}}

{{/* Public helpers that render a whole field, or nothing when the value is empty. */}}

{{- define "gateway-protector.priorityClassName" -}}
{{- with include "gateway-protector._scalar" (dict "ctx" . "key" "priorityClassName") -}}
priorityClassName: {{ . | quote }}
{{- end -}}
{{- end -}}

{{- define "gateway-protector.tolerations" -}}
{{- include "gateway-protector._field" (dict "name" "tolerations" "value" (include "gateway-protector._list" (dict "ctx" . "key" "tolerations") | fromYamlArray)) -}}
{{- end -}}

{{- define "gateway-protector.topologySpreadConstraints" -}}
{{- include "gateway-protector._field" (dict "name" "topologySpreadConstraints" "value" (include "gateway-protector._list" (dict "ctx" . "key" "topologySpreadConstraints") | fromYamlArray)) -}}
{{- end -}}

{{- define "gateway-protector.extraEnvFrom" -}}
{{- include "gateway-protector._field" (dict "name" "envFrom" "value" (include "gateway-protector._list" (dict "ctx" . "key" "extraEnvFrom") | fromYamlArray)) -}}
{{- end -}}

{{- define "gateway-protector.nodeSelector" -}}
{{- include "gateway-protector._field" (dict "name" "nodeSelector" "value" (include "gateway-protector._map" (dict "ctx" . "key" "nodeSelector") | fromYaml)) -}}
{{- end -}}

{{- define "gateway-protector.affinity" -}}
{{- include "gateway-protector._field" (dict "name" "affinity" "value" (include "gateway-protector._map" (dict "ctx" . "key" "affinity") | fromYaml)) -}}
{{- end -}}

{{- define "gateway-protector.workloadAnnotations" -}}
{{- include "gateway-protector._field" (dict "name" "annotations" "value" (include "gateway-protector._map" (dict "ctx" . "key" "annotations") | fromYaml)) -}}
{{- end -}}

{{- define "gateway-protector.podAnnotations" -}}
{{- include "gateway-protector._field" (dict "name" "annotations" "value" (include "gateway-protector._map" (dict "ctx" . "key" "podAnnotations") | fromYaml)) -}}
{{- end -}}

{{- define "gateway-protector.serviceAccountAnnotations" -}}
{{- include "gateway-protector._field" (dict "name" "annotations" "value" (include "gateway-protector._map" (dict "ctx" . "key" "serviceAccount.annotations") | fromYaml)) -}}
{{- end -}}

{{- define "gateway-protector.workloadLabels" -}}
{{- include "gateway-protector._labels" (dict "ctx" . "key" "labels") -}}
{{- end -}}

{{- define "gateway-protector.podLabels" -}}
{{- include "gateway-protector._labels" (dict "ctx" . "key" "podLabels") -}}
{{- end -}}

{{/*
gateway-protector.imagePullSecrets renders "imagePullSecrets:" with the global,
common, and workload lists, in this order.
Each item is a Secret name or a map with a name key. The helper renders a
name as a map. It skips an item with an empty or missing name.
It keeps an item of any other type, and Kubernetes rejects it.
*/}}
{{- define "gateway-protector.imagePullSecrets" -}}
{{- $secrets := list -}}
{{- range include "gateway-protector._concat" (dict "ctx" . "key" "imagePullSecrets") | fromYamlArray -}}
{{- if kindIs "string" . -}}
{{- if . -}}
{{- $secrets = append $secrets (dict "name" .) -}}
{{- end -}}
{{- else if kindIs "map" . -}}
{{- if .name -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- else -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- end -}}
{{- include "gateway-protector._field" (dict "name" "imagePullSecrets" "value" $secrets) -}}
{{- end -}}

{{/* Public helpers that render list entries, or nothing when the list is empty. */}}

{{- define "gateway-protector.extraEnv" -}}
{{- with include "gateway-protector._concat" (dict "ctx" . "key" "extraEnv") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "gateway-protector.extraVolumes" -}}
{{- with include "gateway-protector._concat" (dict "ctx" . "key" "extraVolumes") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "gateway-protector.extraVolumeMounts" -}}
{{- with include "gateway-protector._concat" (dict "ctx" . "key" "extraVolumeMounts") | fromYamlArray -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}
