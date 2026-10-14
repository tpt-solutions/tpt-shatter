# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 TPT Solutions
#
# Run with: opa test infrastructure/policies
package tpt.admission_test

import rego.v1

import data.tpt.admission

digest := "registry.example.internal/tpt-shatter/node@sha256:0000000000000000000000000000000000000000000000000000000000000000"

# A pod that passes every rule. Each test changes one field of it.
good_container := {
	"name": "node",
	"image": digest,
	"securityContext": {
		"runAsNonRoot": true,
		"allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true,
		"capabilities": {"drop": ["ALL"]},
	},
}

good_pod(namespace) := {"request": {
	"namespace": namespace,
	"object": {
		"kind": "Pod",
		"spec": {
			"securityContext": {
				"runAsNonRoot": true,
				"seccompProfile": {"type": "RuntimeDefault"},
			},
			"containers": [good_container],
			"volumes": [
				{"name": "keys", "emptyDir": {"medium": "Memory"}},
				{"name": "state", "persistentVolumeClaim": {"claimName": "tpt-node-state"}},
			],
		},
	},
}}

test_a_conforming_node_pod_is_allowed if {
	count(admission.deny) == 0 with input as good_pod("shatter-node")
}

test_a_privileged_container_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "add", "path": "/request/object/spec/containers/0/securityContext/privileged", "value": true}])
	admission.deny[_] == "container \"node\" is privileged" with input as pod
}

test_a_host_path_volume_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "add", "path": "/request/object/spec/volumes/-", "value": {"name": "host", "hostPath": {"path": "/var"}}}])
	some msg in admission.deny with input as pod
	contains(msg, "hostPath")
}

test_a_disk_backed_emptydir_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "add", "path": "/request/object/spec/volumes/-", "value": {"name": "scratch", "emptyDir": {}}}])
	some msg in admission.deny with input as pod
	contains(msg, "emptyDir on disk")
}

test_a_tag_only_image_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "replace", "path": "/request/object/spec/containers/0/image", "value": "registry.example.internal/tpt-shatter/node:latest"}])
	some msg in admission.deny with input as pod
	contains(msg, "pinned by digest")
}

test_an_image_from_another_registry_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "replace", "path": "/request/object/spec/containers/0/image", "value": "docker.io/someone/node@sha256:0000000000000000000000000000000000000000000000000000000000000000"}])
	some msg in admission.deny with input as pod
	contains(msg, "allowed registry")
}

test_a_writable_root_filesystem_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "replace", "path": "/request/object/spec/containers/0/securityContext/readOnlyRootFilesystem", "value": false}])
	some msg in admission.deny with input as pod
	contains(msg, "readOnlyRootFilesystem")
}

test_an_added_capability_is_denied if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "add", "path": "/request/object/spec/containers/0/securityContext/capabilities/add", "value": ["IPC_LOCK"]}])
	some msg in admission.deny with input as pod
	contains(msg, "adds capabilities")
}

test_the_node_may_not_mount_another_claim if {
	pod := json.patch(good_pod("shatter-node"), [{"op": "replace", "path": "/request/object/spec/volumes/1/persistentVolumeClaim/claimName", "value": "other"}])
	some msg in admission.deny with input as pod
	contains(msg, "may mount only")
}

test_a_pvc_is_allowed_outside_the_node_namespace if {
	pod := json.patch(good_pod("management"), [{"op": "replace", "path": "/request/object/spec/volumes/1/persistentVolumeClaim/claimName", "value": "other"}])
	count(admission.deny) == 0 with input as pod
}
