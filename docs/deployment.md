# Safe deployment guide

## Adoption sequence

1. Run the guard in report-only mode against pull-request manifests and save the JSON report as a CI artifact.
2. Inventory real DNS and egress flows with CNI observability before enabling default deny.
3. Add namespace default-deny policies, then restore cluster DNS with a narrow TCP/UDP 53 rule.
4. Declare reviewed model domains on each AI workload and enforce exact TLS destinations with an FQDN-aware CNI policy.
5. Test model calls, token refresh, telemetry, image pulls, health checks, and failover in a staging cluster.
6. Make `BLOCK` findings merge-blocking only after the existing estate is baselined and exceptions have owners and expiry dates.
7. Require human review for policy changes and use GitOps reconciliation for production rollout.

## Security and privacy

- The evaluator is offline and read-only; it never connects to a cluster or model provider.
- Reports contain resource names and destinations. Treat them as internal operational metadata and apply retention controls.
- Pin CI dependencies, use a read-only token, and protect changes to the policy file and workflow.
- Do not send raw manifests, secrets, tokens, or internal domain names to an external language model.
- AI may explain deterministic findings or draft a patch, but cannot add destinations, change workload annotations, approve, or deploy.

## Reliability and failure modes

- A CNI without NetworkPolicy enforcement makes a passing manifest ineffective. Verify the cluster dataplane.
- Standard NetworkPolicy cannot express FQDN destinations. The sample uses Cilium; equivalent controls need their own adapter and tests.
- DNS policy behavior depends on the CNI and DNS topology. Validate NodeLocal DNSCache and custom CoreDNS labels.
- Vendor endpoints may use redirects or regional hostnames. Prefer documented endpoint sets and staged flow observation over wildcard allowlists.
- Default deny can interrupt telemetry, identity, package, or certificate flows. Use service-specific canaries and rollback-ready Git commits.
- Static policy cannot prove runtime enforcement, TLS identity, DNS integrity, or the safety of the remote service.

## Operational ownership

Platform engineering owns the policy schema and CI integration. Security approves destination classes and exception rules. Service owners declare the minimum endpoint set and validate application behavior. SRE tracks blocked-flow alerts, false positives, failed model calls, and rollback time.

## Measurable outcomes

- Percentage of AI workloads covered by default-deny egress.
- Percentage with exact approved model-domain enforcement.
- Count and age of wildcard or broad-egress exceptions.
- Cloud-metadata reachability findings per release.
- Policy false-positive rate and median remediation time.
- Failed inference requests caused by policy changes.
- Mean time to detect and roll back an unsafe egress change.
