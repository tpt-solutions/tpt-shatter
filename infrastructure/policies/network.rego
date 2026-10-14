# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 TPT Solutions
#
# Admission rules for NetworkPolicy objects in the vault namespaces. These enforce spec
# 6.1: vault subnets are isolated from each other, and a vault sends nothing.
#
# Admission sees one object at a time. It can refuse a policy that opens a vault to the
# wrong source, but it cannot prove that a vault namespace has a default-deny policy. That
# needs cluster-wide data (Gatekeeper's sync), which is not wired yet. See README.md.
package tpt.network

import rego.v1

vault_namespaces := {"vault-a", "vault-b", "vault-c"}

# The one namespace allowed to reach a vault.
node_namespace := "shatter-node"

in_vault_namespace if {
	input.request.namespace in vault_namespaces
}

# A policy that allows all sources for a vault (no `from`, or an empty one).
deny contains msg if {
	in_vault_namespace
	some rule in input.request.object.spec.ingress
	count(object.get(rule, "from", [])) == 0
	msg := "a vault namespace may not accept traffic from every source"
}

# A vault may receive from the node namespace only.
deny contains msg if {
	in_vault_namespace
	some rule in input.request.object.spec.ingress
	some peer in object.get(rule, "from", [])
	some other in vault_namespaces
	namespace_selected(peer, other)
	msg := sprintf("vault namespace %q may not accept traffic from vault namespace %q", [input.request.namespace, other])
}

deny contains msg if {
	in_vault_namespace
	some rule in input.request.object.spec.ingress
	some peer in object.get(rule, "from", [])
	peer.ipBlock
	msg := "a vault namespace may not accept traffic from an IP block; allow only the node namespace"
}

deny contains msg if {
	in_vault_namespace
	some rule in input.request.object.spec.ingress
	some peer in object.get(rule, "from", [])
	peer.namespaceSelector
	not namespace_selector_is_node(peer)
	msg := "a vault namespace may accept traffic only from the shatter-node namespace"
}

# A vault sends nothing: no egress rules at all.
deny contains msg if {
	in_vault_namespace
	count(object.get(input.request.object.spec, "egress", [])) > 0
	msg := "a vault namespace may not allow any egress"
}

namespace_selected(peer, ns) if {
	peer.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == ns
}

namespace_selector_is_node(peer) if {
	peer.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == node_namespace
}
