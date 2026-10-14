# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 TPT Solutions
#
# Admission rules for tpt-shatter workloads. Each `deny` message is returned to the client.
# Works as an OPA/Gatekeeper validating webhook over AdmissionReview input, where the
# object is at input.request.object.
package tpt.admission

import rego.v1

# Image registries that may run. This default is a placeholder. A deployment overrides it
# with its own registry, for example through OPA data, rather than editing this file.
default allowed_registry_prefixes := ["registry.example.internal/tpt-shatter/"]

# Namespaces that hold tpt-shatter workloads. Rules below apply to these.
tpt_namespaces := {"shatter-node", "vault-a", "vault-b", "vault-c"}

# The only PVC a node may mount. Spec 6.2 wants no persistent volume on the assembler
# host; this one exists because the node keeps its audit chain and orphan queue on disk.
# Remove this exception when the state moves off the host (see README.md).
allowed_node_state_claim := "tpt-node-state"

# The pod spec of any workload kind that carries one.
pod_spec := input.request.object.spec if {
	input.request.object.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.object.kind != "Pod"
}

# Every container, including init containers, as one array.
containers := array.concat(pod_spec.containers, object.get(pod_spec, "initContainers", []))

in_tpt_namespace if {
	input.request.namespace in tpt_namespaces
}

# ---- Pod-level rules --------------------------------------------------------------

deny contains msg if {
	pod_spec.hostNetwork == true
	msg := "hostNetwork is not allowed"
}

deny contains msg if {
	pod_spec.hostPID == true
	msg := "hostPID is not allowed"
}

deny contains msg if {
	pod_spec.hostIPC == true
	msg := "hostIPC is not allowed"
}

deny contains msg if {
	some v in pod_spec.volumes
	v.hostPath
	msg := sprintf("volume %q uses hostPath, which is not allowed", [v.name])
}

deny contains msg if {
	pod_spec.securityContext.runAsNonRoot != true
	not pod_level_nonroot_on_containers
	msg := "pod must set securityContext.runAsNonRoot: true"
}

# A pod passes if every container sets runAsNonRoot itself. Checked per container below.
pod_level_nonroot_on_containers if {
	count(containers) > 0
	every c in containers {
		c.securityContext.runAsNonRoot == true
	}
}

deny contains msg if {
	pod_spec.securityContext.seccompProfile.type != "RuntimeDefault"
	msg := "pod must set securityContext.seccompProfile.type: RuntimeDefault"
}

# ---- Container-level rules --------------------------------------------------------

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("container %q is privileged", [c.name])
}

deny contains msg if {
	some c in containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("container %q must set allowPrivilegeEscalation: false", [c.name])
}

deny contains msg if {
	some c in containers
	c.securityContext.readOnlyRootFilesystem != true
	msg := sprintf("container %q must set readOnlyRootFilesystem: true", [c.name])
}

deny contains msg if {
	some c in containers
	not "ALL" in object.get(c.securityContext.capabilities, "drop", [])
	msg := sprintf("container %q must drop ALL capabilities", [c.name])
}

deny contains msg if {
	some c in containers
	count(object.get(c.securityContext.capabilities, "add", [])) > 0
	msg := sprintf("container %q adds capabilities, which is not allowed", [c.name])
}

deny contains msg if {
	some c in containers
	not image_digest_pinned(c.image)
	msg := sprintf("container %q image %q must be pinned by digest", [c.name, c.image])
}

deny contains msg if {
	some c in containers
	not image_from_allowed_registry(c.image)
	msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}

image_digest_pinned(image) if {
	contains(image, "@sha256:")
}

image_from_allowed_registry(image) if {
	some prefix in allowed_registry_prefixes
	startswith(image, prefix)
}

# ---- Storage rules, for tpt namespaces --------------------------------------------
#
# Key material and fragments must not reach disk except through a volume the spec allows.
# A memory-backed emptyDir is RAM only. A PVC is allowed on the node only for its state
# claim, and on vaults for their own fragment volume (claimed through volumeClaimTemplates,
# which this rule does not see on the StatefulSet's pod spec).

deny contains msg if {
	in_tpt_namespace
	some v in object.get(pod_spec, "volumes", [])
	v.emptyDir

	# An absent medium is disk-backed, so default it to "" rather than leaving it undefined.
	object.get(v.emptyDir, "medium", "") != "Memory"
	msg := sprintf("volume %q is an emptyDir on disk; tpt workloads may use only medium: Memory", [v.name])
}

deny contains msg if {
	input.request.namespace == "shatter-node"
	some v in object.get(pod_spec, "volumes", [])
	v.persistentVolumeClaim
	v.persistentVolumeClaim.claimName != allowed_node_state_claim
	msg := sprintf("volume %q claims %q; the node may mount only %q", [v.name, v.persistentVolumeClaim.claimName, allowed_node_state_claim])
}
