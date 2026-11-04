"""Deterministic correlation of AI workloads and Kubernetes egress policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Iterable

import yaml

METADATA_IPS = (ip_address("169.254.169.254"), ip_address("100.100.100.200"))


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str
    remediation: str


@dataclass(frozen=True)
class AnalysisReport:
    decision: str
    score: int
    workloads_checked: int
    findings: tuple[Finding, ...]
    advisory_ai_prompt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "score": self.score,
            "workloads_checked": self.workloads_checked,
            "findings": [asdict(item) for item in self.findings],
            "advisory_ai_prompt": self.advisory_ai_prompt,
        }


def load_documents(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        candidates = sorted(path.rglob("*.y*ml")) if path.is_dir() else [path]
        for candidate in candidates:
            with candidate.open("r", encoding="utf-8") as handle:
                documents.extend(doc for doc in yaml.safe_load_all(handle) if isinstance(doc, dict))
    return documents


def _id(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") or {}
    return f"{document.get('kind', 'Unknown')}/{metadata.get('namespace', 'default')}/{metadata.get('name', 'unnamed')}"


def _finding(rule: str, severity: str, resource: str, message: str, remediation: str) -> Finding:
    return Finding(rule, severity, resource, message, remediation)


def _labels_match(selector: dict[str, Any], labels: dict[str, str]) -> bool:
    match_labels = selector.get("matchLabels") if "matchLabels" in selector else selector
    return bool(match_labels) and all(labels.get(key) == value for key, value in (match_labels or {}).items())


def _is_default_deny(policy: dict[str, Any]) -> bool:
    spec = policy.get("spec") or {}
    return spec.get("podSelector") == {} and "Egress" in (spec.get("policyTypes") or []) and not spec.get("egress")


def _metadata_exposed(ip_block: dict[str, Any]) -> bool:
    try:
        network = ip_network(ip_block.get("cidr", ""), strict=False)
        exceptions = [ip_network(item, strict=False) for item in ip_block.get("except") or []]
    except ValueError:
        return False
    return any(address in network and not any(address in excluded for excluded in exceptions) for address in METADATA_IPS)


def analyze_documents(documents: list[dict[str, Any]]) -> AnalysisReport:
    workloads: list[dict[str, Any]] = []
    network_policies: dict[str, list[dict[str, Any]]] = {}
    cilium_policies: dict[str, list[dict[str, Any]]] = {}

    for document in documents:
        metadata = document.get("metadata") or {}
        namespace = metadata.get("namespace", "default")
        kind = document.get("kind")
        if kind == "Deployment":
            labels = (((document.get("spec") or {}).get("template") or {}).get("metadata") or {}).get("labels") or {}
            if labels.get("platform.example.com/workload-class") == "ai-inference":
                workloads.append(document)
        elif kind == "NetworkPolicy":
            network_policies.setdefault(namespace, []).append(document)
        elif kind in {"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy"}:
            cilium_policies.setdefault(namespace, []).append(document)

    findings: list[Finding] = []
    for workload in workloads:
        resource = _id(workload)
        metadata = workload.get("metadata") or {}
        namespace = metadata.get("namespace", "default")
        template = (workload.get("spec") or {}).get("template") or {}
        pod_metadata = template.get("metadata") or {}
        labels = pod_metadata.get("labels") or {}
        annotations = pod_metadata.get("annotations") or {}
        pod_spec = template.get("spec") or {}
        desired_domains = {item.strip().lower() for item in annotations.get("security.platform.example.com/approved-model-domains", "").split(",") if item.strip()}

        if not desired_domains:
            findings.append(_finding("EG001", "BLOCK", resource, "No approved model endpoint domains are declared.", "Declare an explicit comma-separated approved-model-domains annotation."))
        if pod_spec.get("serviceAccountName", "default") == "default":
            findings.append(_finding("EG002", "REVIEW", resource, "The workload uses the default ServiceAccount.", "Use a dedicated workload identity with least privilege."))

        native = network_policies.get(namespace, [])
        if not any(_is_default_deny(policy) for policy in native):
            findings.append(_finding("EG003", "BLOCK", resource, "The namespace has no default-deny egress NetworkPolicy.", "Add a podSelector: {} egress-isolation policy before allow rules."))

        selected_native = [policy for policy in native if _labels_match(((policy.get("spec") or {}).get("podSelector") or {}), labels)]
        dns_ok = False
        for policy in selected_native:
            for rule in (policy.get("spec") or {}).get("egress") or []:
                destinations = rule.get("to")
                ports = rule.get("ports") or []
                if not destinations:
                    findings.append(_finding("EG004", "BLOCK", _id(policy), "An egress rule has no bounded destination.", "Set namespace/pod selectors or an explicit IP block."))
                if not ports:
                    findings.append(_finding("EG005", "BLOCK", _id(policy), "An egress rule has no bounded destination port.", "Restrict each allow rule to required protocols and ports."))
                for destination in destinations or []:
                    ip_block = destination.get("ipBlock") or {}
                    if ip_block and _metadata_exposed(ip_block):
                        findings.append(_finding("EG006", "BLOCK", _id(policy), "An IP allow rule exposes a cloud metadata endpoint.", "Exclude metadata IPs or remove the broad IP range."))
                    ns = (destination.get("namespaceSelector") or {}).get("matchLabels") or {}
                    pod = (destination.get("podSelector") or {}).get("matchLabels") or {}
                    if ns.get("kubernetes.io/metadata.name") == "kube-system" and pod.get("k8s-app") in {"kube-dns", "coredns"}:
                        port_pairs = {(str(item.get("protocol", "TCP")), int(item.get("port", 0))) for item in ports}
                        if port_pairs and port_pairs.issubset({("UDP", 53), ("TCP", 53)}) and any(port == 53 for _, port in port_pairs):
                            dns_ok = True
        if not dns_ok:
            findings.append(_finding("EG007", "REVIEW", resource, "No narrowly scoped DNS egress rule was found.", "Allow only TCP/UDP 53 to the cluster DNS pods."))

        selected_cilium = [policy for policy in cilium_policies.get(namespace, []) if _labels_match(((policy.get("spec") or {}).get("endpointSelector") or {}), labels)]
        observed_domains: set[str] = set()
        for policy in selected_cilium:
            for rule in (policy.get("spec") or {}).get("egress") or []:
                fqdn_entries = rule.get("toFQDNs") or []
                observed_domains.update(str(item.get("matchName", "")).lower() for item in fqdn_entries if item.get("matchName"))
                wildcard_patterns = [item.get("matchPattern") for item in fqdn_entries if item.get("matchPattern")]
                if wildcard_patterns:
                    findings.append(_finding("EG008", "REVIEW", _id(policy), "Wildcard FQDN egress is configured.", "Prefer exact approved model endpoint names and review vendor-specific subdomain needs."))
                for port_rule in rule.get("toPorts") or []:
                    allowed = {(str(port.get("protocol", "TCP")), int(port.get("port", 0))) for port in port_rule.get("ports") or []}
                    if not allowed or not allowed.issubset({("TCP", 443)}):
                        findings.append(_finding("EG009", "BLOCK", _id(policy), "Model endpoint egress is not limited to TCP 443.", "Restrict approved external model endpoints to TLS on TCP 443."))

        if desired_domains and not selected_cilium:
            findings.append(_finding("EG010", "BLOCK", resource, "No FQDN-aware policy selects the AI workload.", "Add a CiliumNetworkPolicy or equivalent L7/FQDN-aware control."))
        missing = desired_domains - observed_domains
        if missing:
            findings.append(_finding("EG011", "BLOCK", resource, f"Approved domains are not enforced: {', '.join(sorted(missing))}.", "Add exact FQDN allow rules for every declared endpoint."))
        undeclared = observed_domains - desired_domains
        if undeclared:
            findings.append(_finding("EG012", "REVIEW", resource, f"Policy allows undeclared domains: {', '.join(sorted(undeclared))}.", "Remove them or add reviewed business justification to the workload annotation."))

    blocks = sum(item.severity == "BLOCK" for item in findings)
    reviews = sum(item.severity == "REVIEW" for item in findings)
    decision = "BLOCK" if blocks else "REVIEW" if reviews else "PASS"
    score = max(0, 100 - blocks * 20 - reviews * 7)
    prompt = (
        "Explain the deterministic Kubernetes egress findings and draft a minimal policy patch. "
        "Do not add destinations, change the approved-domain annotation, approve a merge, or deploy."
    )
    return AnalysisReport(decision, score, len(workloads), tuple(findings), prompt)
