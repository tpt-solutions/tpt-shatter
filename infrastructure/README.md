# Infrastructure

Kubernetes manifests and OPA policies for the spec section 6.1 isolation model. This is a
starting point, not a deployable release. Read the gaps below before applying anything.

## Layout

| Path | What it holds |
|---|---|
| `k8s/namespaces.yaml` | One namespace per network segment, each on the `restricted` Pod Security Standard. |
| `k8s/network-policies.yaml` | Default-deny per namespace, and the allowed flows of spec 6.1. |
| `k8s/node.yaml` | The `tpt-shatter-node` Deployment, config, state volume, and Service. |
| `k8s/vault-services.yaml` | One `tpt-shatter-vault` StatefulSet per vault, in its own namespace. |
| `policies/admission.rego` | Pod and workload rules: no privileged, no hostPath, pinned images, read-only root, dropped capabilities, memory-only scratch volumes. |
| `policies/network.rego` | NetworkPolicy rules: a vault accepts only the node, and sends nothing. |
| `policies/*_test.rego` | Unit tests for both files. |

Apply in this order: `namespaces.yaml`, then `network-policies.yaml`, then the workloads.
The policies are meant to run as an OPA or Gatekeeper validating webhook.

## Checks run

- All manifests parse as YAML, and the node's embedded `node.json` parses as JSON.
- `opa test infrastructure/policies`: 16 of 16 pass (OPA 1.4.2).
- The admission and network rules run against the shipped Deployments, StatefulSets, and
  vault NetworkPolicies. None of them is denied.
- Not run: `kubectl apply --dry-run=server`, and any test on a live cluster. This machine has
  no cluster, so the object shapes are checked only by reading them. The rules are tested
  against hand-built objects, not against a real admission chain.

## Spec 6.1 mapping

| Segment | Spec rule | Implementation | Status |
|---|---|---|---|
| Vault subnets | Inbound from assembler, shredder, canary only; no outbound; isolated from each other | Each vault namespace is default-deny. It accepts TCP 7443 from `shatter-node` pods only, and has no egress rules. | Built. The node process is the source for all three roles, so the rule admits the node. |
| Gateway (DMZ) | Inbound from Internet; outbound to assembler only | `shatter-edge` may reach `shatter-node` on 8443 only. | Partial. The gateway is not separate from the node yet (see gap 1). The assembler link is built. |
| Assembler / shredder (private) | Inbound from gateway or ingestion; outbound to vaults | `shatter-node` accepts 8443 from the edge, 8444 from issuer clients, and 9100 from management. Egress is 7443 to vault namespaces, and DNS. | Built, but one process holds all of these roles. |
| Canary (management) | Outbound to all vaults and the gateway | Canary runs inside the node, so it is not a separate segment. The management namespace only scrapes metrics. | Not as specified (see gap 1). |
| Analytics (insight-vault) | Inbound from emitter only; outbound to BI | Not deployed. Exports are CSV files on the node's state volume. Delivery to BI is not built. | Gap. |

## Gaps and decisions needed

1. **One process, several roles.** The node binary runs the gateway, assembler, shredder,
   canary, issuer, and analytics feed together. The spec needs the gateway in a DMZ and the
   assembler in a private subnet, which cannot be expressed with one pod. The current
   `shatter-edge` rule reaches the whole node.

   Progress: the gateway is its own binary (`tpt-shatter-gateway-service`). It has no vault,
   assembler, shredder, or canary crates in its normal dependency tree. It reads records from
   the assembler service over mTLS, and records reads on its own audit chain under its own key.
   Canary alarms reach the gateway through its alarm listener (mTLS, management network). The
   node pushes a new signing key there when it fires. Still open before the split runs on
   its own host: the assembler service does not observe canary reads (DECISIONS.md, "Canary
   alarm propagation"). Not deployed: this directory has no gateway or assembler workload yet.

2. **Spec 6.2 forbids persistent volumes on the assembler host, but the node needs disk.**
   The audit chain, the orphan queue, and the analytics log live in `state_dir`. The
   `tpt-node-state` PVC is the one exception the policy allows (`allowed_node_state_claim`
   in `admission.rego`). Decide where that state should live. The alternatives are an
   off-host store, or a separate analytics pod. Record the decision in DECISIONS.md, then
   remove the exception.

3. **Key delivery is not automated.** `TPT_KEYS_DIR` and the vault key file are
   memory-backed volumes. Nothing here fills them. The custody ceremony in `docs/RUNBOOK.md`
   is manual, and the KMS unwrap is not tested against a live cloud KMS. The keys volume
   is mounted read-only in the containers, so the fill step must run as a separate
   process, not as a container in these manifests.

4. **Certificates are not issued here.** The Secrets are referenced but not created:
   - `tpt-node-tls`: the gateway's server certificate.
   - `tpt-gateway-client-ca`: the CA that gateway clients must chain to.
   - `tpt-node-vault-client`: the node's certificate and key for the vault services, and
     the vault CA.
   - `tpt-vault-tls`, per vault namespace: each vault's server certificate, with the name
     in its `server_names` entry as its SAN.
   - `tpt-node-client-ca`, per vault namespace: the CA that node certificates chain to.

   Certificate issuance and rotation are still open (todo.md, Phase 9 and Phase 12).

5. **Vault names need the new config field.** The node reads one certificate name per
   vault from `remote_vaults.server_names`. The single `server_name` cannot express three
   namespaces. This field was added in this change (`tpt-shatter-node` `RemoteVaults`).

6. **Schema is a placeholder.** `node.yaml` embeds the field mapping from the node example.
   Replace it with the deployment's real schema, which must be reviewed like code.

7. **The CNI must enforce NetworkPolicy.** Without an enforcing CNI, the policies are
   accepted and do nothing. Confirm this on the target cluster before relying on them.

8. **Admission cannot see the whole namespace.** `network.rego` checks each policy as it
   arrives. It cannot confirm that a default-deny policy exists in every vault namespace.
   That check needs cluster-wide data (Gatekeeper's sync), which is not wired.

9. **Images are placeholders.** The digests and registry (`registry.example.internal`) are
   placeholders. The build pipeline (static musl binaries, distroless base) is not built
   (todo.md, Phase 12).

## Terraform

Not started. The spec asks for cloud-agnostic Terraform, but Terraform resources are
provider-specific, so this layer needs a target cloud first. The Terraform binary is also
not installed on this machine. The segment list in the mapping table above is the input the
Terraform network module will need.
