# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 TPT Solutions
#
# Run with: opa test infrastructure/policies
package tpt.network_test

import rego.v1

import data.tpt.network

node_peer := {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "shatter-node"}}}

vault_b_peer := {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "vault-b"}}}

# A vault policy that accepts the node only, with no egress.
good_policy(namespace) := {"request": {
	"namespace": namespace,
	"object": {"spec": {
		"podSelector": {},
		"policyTypes": ["Ingress", "Egress"],
		"ingress": [{"from": [node_peer], "ports": [{"protocol": "TCP", "port": 7443}]}],
	}},
}}

test_a_vault_accepting_only_the_node_is_allowed if {
	count(network.deny) == 0 with input as good_policy("vault-a")
}

test_a_vault_accepting_another_vault_is_denied if {
	policy := json.patch(good_policy("vault-a"), [{"op": "replace", "path": "/request/object/spec/ingress/0/from", "value": [vault_b_peer]}])
	some msg in network.deny with input as policy
	contains(msg, "may not accept traffic from vault namespace")
}

test_a_vault_accepting_every_source_is_denied if {
	policy := json.patch(good_policy("vault-a"), [{"op": "remove", "path": "/request/object/spec/ingress/0/from"}])
	some msg in network.deny with input as policy
	contains(msg, "every source")
}

test_a_vault_accepting_an_ip_block_is_denied if {
	policy := json.patch(good_policy("vault-a"), [{"op": "replace", "path": "/request/object/spec/ingress/0/from", "value": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}])
	some msg in network.deny with input as policy
	contains(msg, "IP block")
}

test_a_vault_with_egress_is_denied if {
	policy := json.patch(good_policy("vault-a"), [{"op": "add", "path": "/request/object/spec/egress", "value": [{"to": [node_peer]}]}])
	some msg in network.deny with input as policy
	contains(msg, "egress")
}

test_a_policy_outside_the_vault_namespaces_is_not_restricted_here if {
	count(network.deny) == 0 with input as good_policy("shatter-node")
}
