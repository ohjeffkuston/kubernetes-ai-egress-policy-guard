# Deployment, learning, and interview summary

Hello Jeffrey,

Day 21 is Kubernetes AI Egress Policy Guard, a production-focused security project for AI workloads that require outbound model access without unrestricted internet or cloud-metadata reachability.

## Production problem and design

The project correlates labeled Deployments, namespace default-deny policy, narrow DNS rules, and Cilium exact-FQDN policy. The enforcement engine is deterministic. Optional AI can explain findings or draft a minimal patch, but it cannot add destinations, alter workload intent, approve a merge, or deploy.

## Deployment guidance

Run it as a report-only CI job first. Observe live flows, validate the CNI, baseline existing services, add default deny, restore DNS and endpoint access incrementally, test inference and failover in staging, retain evidence, and require owners plus expiry for exceptions. Use GitOps and human approval for production changes.

## Security and reliability lessons

Native NetworkPolicy is additive and layer 3/4; FQDN-aware controls need CNI-specific capability. Default deny can break DNS, telemetry, identity, certificate, and model-provider flows. Static analysis cannot prove runtime enforcement or remote-service safety, so flow visibility and canary tests are still required. Reports may contain internal domains and should be treated as operationally sensitive.

## Validation and outcomes

The unit suite covers twelve paths, including default deny, DNS, unbounded rules, metadata exposure, endpoint drift, wildcards, and non-TLS traffic. Measure policy coverage, wildcard exception age, metadata findings, false-positive rate, inference failures caused by policy, remediation time, and rollback time.

## Interview positioning

Lead with the production trust-boundary problem. Explain why native NetworkPolicy alone cannot safely express changing DNS-based model endpoints. Discuss the trade-off between exact domains and operational flexibility, the decision to keep AI advisory-only, and the staged rollout needed to avoid an outage. This demonstrates Kubernetes networking, cloud security, GitOps, CI/CD, policy-as-code, deterministic testing, failure-mode thinking, and AI-infrastructure operations.

Repository: https://github.com/ohjeffkuston/kubernetes-ai-egress-policy-guard

Regards,
Jeffrey Ikuoyemwen
