# Demand and source validation

Checked 2026-11-04 (America/Detroit).

## Authoritative technical sources

- Kubernetes NetworkPolicy documentation explains that namespaces allow ingress and egress by default, shows default-deny egress, and warns that DNS must be allowed separately: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Kubernetes NetworkPolicy API documents additive allow rules and the risk of rules with missing destinations or ports: https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/
- Kubernetes security checklist recommends default-deny network policies and filtering workload access to cloud metadata APIs: https://kubernetes.io/docs/concepts/security/security-checklist/
- Cilium FQDN policy documentation describes DNS-aware controls for workloads that must reach named external services: https://docs.cilium.io/en/stable/security/dns/

## Current role evidence

- AI/ML platform engineering: remote U.S. role, $136K-$240K, requires Kubernetes, Terraform, multi-tenant AI infrastructure, and production operations: https://jobs.ashbyhq.com/Deepgram/f424ef6a-c27f-4984-9e77-40a1ad16ae28/
- AI-security platform engineering: remote U.S. role at the intersection of Kubernetes, networking, secure automation, and AI/ML security: https://job-boards.greenhouse.io/hiddenlayer/jobs/4953694007
- Cloud platform engineering: remote U.S. role, $140K-$175K, requires security baselines, lifecycle automation, cloud platforms, and AI-assisted tooling: https://job-boards.greenhouse.io/zscaler/jobs/5208829007
- SRE/infrastructure engineering: remote U.S./Canada role, $175K-$275K, requires secure cloud-scale production systems and Kubernetes familiarity: https://jobs.ashbyhq.com/workos/cff5a16f-fd1c-4b64-9b66-8a8321122375

## Demand rationale

AI services commonly need outbound access to model APIs, registries, telemetry, and internal gateways. Kubernetes NetworkPolicy is intentionally layer 3/4 and additive, while model endpoints are often DNS-addressed and change IPs. That combination creates a credible platform-security problem: teams need default-deny isolation, narrowly scoped DNS, metadata protection, and an FQDN-aware control without giving an AI assistant authority to widen production egress. Current postings repeatedly combine Kubernetes, networking, security automation, AI infrastructure, and production reliability.

These postings validate the problem domain, not candidate fit or application eligibility.
